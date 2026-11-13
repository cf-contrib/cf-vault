//! A tiny scripted HTTP server on a loopback port, and a raw HTTP client that never follows
//! redirects. Everything uses fake credentials.

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

#[derive(Clone, Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The urlencoded body (or query string) as a map.
    pub fn form(&self) -> HashMap<String, String> {
        parse_pairs(&self.body)
    }

    pub fn query_map(&self) -> HashMap<String, String> {
        parse_pairs(&self.query)
    }
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                if let Ok(value) = u8::from_str_radix(hex, 16) {
                    out.push(value);
                    i += 2;
                } else {
                    out.push(b'%');
                }
            }
            other => out.push(other),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn parse_pairs(text: &str) -> HashMap<String, String> {
    text.split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(k), percent_decode(v))
        })
        .collect()
}

#[derive(Clone, Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Response {
    pub fn json(status: u16, body: impl Into<String>) -> Self {
        Response {
            status,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: body.into(),
        }
    }

    pub fn redirect(location: &str) -> Self {
        Response {
            status: 302,
            headers: vec![("Location".into(), location.into())],
            body: String::new(),
        }
    }
}

pub type Handler = Box<dyn Fn(&Request) -> Response + Send + Sync>;

pub struct Server {
    pub port: u16,
    requests: Arc<Mutex<Vec<Request>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut data = Vec::new();
    let mut buffer = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut buffer).ok()?;
        if n == 0 {
            return None;
        }
        data.extend_from_slice(&buffer[..n]);
        if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let head = String::from_utf8_lossy(&data[..header_end]).into_owned();
    let headers: Vec<(String, String)> = head
        .lines()
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let length = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    while data.len() < header_end + length {
        let n = stream.read(&mut buffer).ok()?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buffer[..n]);
    }
    let first = head.lines().next()?;
    let mut parts = first.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
    Some(Request {
        method,
        path: path.to_string(),
        query: query.to_string(),
        headers,
        body: String::from_utf8_lossy(&data[header_end..]).into_owned(),
    })
}

impl Server {
    /// Starts a server. `make` receives the base URL (`http://127.0.0.1:<port>`) and returns the
    /// handler, so documents can name their own address.
    pub fn start(make: impl FnOnce(String) -> Handler) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let handler: Arc<Handler> = Arc::new(make(format!("http://127.0.0.1:{port}")));
        let requests: Arc<Mutex<Vec<Request>>> = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let (reqs, stopped) = (requests.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            let mut workers = Vec::new();
            while !stopped.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let (reqs, handler) = (reqs.clone(), handler.clone());
                        workers.push(std::thread::spawn(move || {
                            let _ = stream.set_nonblocking(false);
                            let Some(request) = read_request(&mut stream) else {
                                return;
                            };
                            reqs.lock().unwrap().push(request.clone());
                            let response = handler(&request);
                            let mut reply = format!("HTTP/1.1 {} X\r\n", response.status);
                            for (k, v) in &response.headers {
                                reply.push_str(&format!("{k}: {v}\r\n"));
                            }
                            reply.push_str(&format!(
                                "Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                                response.body.len(),
                                response.body
                            ));
                            let _ = stream.write_all(reply.as_bytes());
                        }));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(10)),
                }
            }
            for worker in workers {
                let _ = worker.join();
            }
        });
        Server {
            port,
            requests,
            stop,
            thread: Some(thread),
        }
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }

    /// Requests whose path is `path`.
    pub fn hits(&self, path: &str) -> Vec<Request> {
        self.requests()
            .into_iter()
            .filter(|r| r.path == path)
            .collect()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A GET that never follows redirects: `(status, headers, body)`.
pub fn get(url: &str) -> (u16, Vec<(String, String)>, String) {
    let rest = url.strip_prefix("http://").expect("http url");
    let (host, path) = rest
        .split_once('/')
        .map(|(h, p)| (h, format!("/{p}")))
        .unwrap_or((rest, "/".into()));
    let mut stream = TcpStream::connect(host).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = String::new();
    let _ = stream.read_to_string(&mut raw);
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    (status, headers, body.to_string())
}
