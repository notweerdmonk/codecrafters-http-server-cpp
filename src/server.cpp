#include <iostream>
#include <cstdlib>
#include <string>
#include <cstring>
#include <sstream>
#include <vector>
#include <map>
#include <algorithm>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <regex>
#include <utility>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <getopt.h>

static
std::atomic<bool> exit_condition{false};

static
struct sigaction old_sa;

void sigint_handler(int sig) {
  sigaction(SIGINT, &old_sa, NULL);
  exit_condition = true;
}

void setup_sigint_handler() {
  struct sigaction sa;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = sigint_handler;
  sigaction(SIGINT, &sa, &old_sa);
}

template<typename T, T guard, size_t max_size = 8>
class queue {
  T data[max_size];
  ssize_t out, in, qsize;

 public:

  queue() : out(0), in(0), qsize(0) {
  }

  inline
  size_t size() {
    return qsize;
  }

  inline
  bool empty() {
    return qsize == 0;
  }

  inline
  bool full() {
    return qsize == max_size;
  }

  void enqueue(T t) {
    if (full()) {
      return;
    }

    data[in] = t;
    if (++in == max_size) {
      in = 0;
    }

    qsize++;
  }

  T peek() {
    if (empty()) {
      return guard;
    }

    return data[out];
  }

  T dequeue() {
    if (empty()) {
      return guard;
    }

    T t = data[out];
    if (++out == max_size) {
      out = 0;
    }

    qsize--;

    return t;
  }

  // Iterator class for queue
  friend class iterator;

#if __cplusplus >= 202002L

  class iterator {
    queue& q;
    T* ptr;
    size_t remaining;

   public:
    using iterator_category = std::forward_iterator_tag;
    using value_type = T;
    using element_type = T;
    using difference_type = std::ptrdiff_t;
    using pointer = T*;
    using reference = T&;

    iterator(queue& q, T* p) : q(q), ptr(p), remaining(q.size()) {}

    iterator& operator++() {
      ++ptr;
      --remaining;
      if (remaining == 0) {
        ptr = &q.data[max_size];
      } else if (ptr == &q.data[max_size]) {
        ptr = q.data;
      }
      return *this;
    }

    iterator operator++(int) {
      iterator tmp = *this;
      ++(*this);
      return tmp;
    }

    bool operator==(const iterator& other) const {
      return ptr == other.ptr;
    }

    bool operator!=(const iterator& other) const {
      return !(*this == other);
    }

    reference operator*() const {
      return *ptr;
    }

    pointer operator->() const {
      return ptr;
    }
  };

  iterator begin() {
    return iterator(*this, &data[out]);
  }

  iterator end() {
    return iterator(*this, &data[max_size]);
  }

#else

  class iterator : public std::iterator<std::forward_iterator_tag, T> {
    queue& q;
    T* ptr;
    size_t remaining;

   public:
    iterator(queue& q, T* p) : q(q), ptr(p), remaining(q.size()) {}

    iterator& operator++() {
      ++ptr;
      --remaining;
      if (remaining == 0) {
        ptr = &q.data[max_size];
      } else if (ptr == &q.data[max_size]) {
        ptr = q.data;
      }
      return *this;
    }

    iterator operator++(int) {
      iterator tmp = *this;
      ++(*this);
      return tmp;
    }

    bool operator==(const iterator& other) const {
      return ptr == other.ptr;
    }

    bool operator!=(const iterator& other) const {
      return !(*this == other);
    }

    T& operator*() const {
      return *ptr;
    }

    T* operator->() const {
      return ptr;
    }
  };

  iterator begin() {
    return iterator(*this, &data[out]);
  }

  iterator end() {
    return iterator(*this, &data[max_size]);
  }

#endif

};

template<typename task_type, size_t max_concurrent_conn = 10>
class thread_pool {
  using pointer = task_type*;
  queue<pointer, nullptr, max_concurrent_conn> q;
  std::thread pool[max_concurrent_conn];
  std::mutex mtx;
  std::condition_variable cv;
  std::atomic<bool> exit_condition;

 public:
  thread_pool() : exit_condition(false) {
    for (auto i = 0; i < max_concurrent_conn; i++) {
      pool[i] = std::thread([this]() {
        while (!this->exit_condition) {
          std::unique_lock<std::mutex> lock(this->mtx);

          // check condition, if not met wait on the condition variable
          // this atomically releases the mutex and puts the thread to sleep
          // when notified reacquire the mutex and recheck the condition
          this->cv.wait(lock, [&]() {
            return !this->q.empty() || this->exit_condition;
          });
          if (this->exit_condition) {
            return;
          }

          pointer ptask = this->q.dequeue();
          lock.unlock();
          if (!ptask) {
            continue;
          }
          (*ptask)();
          delete ptask;
        }
      });
    }
  }

  size_t size() {
    std::lock_guard<std::mutex> lock(mtx);
    return q.size();
  }

  void enqueue(pointer ptask) {
    std::lock_guard<std::mutex> lock(mtx);
    q.enqueue(ptask);
    cv.notify_one();
  }

  void exit() {
    if (exit_condition) {
      return;
    }

    exit_condition = true;
    cv.notify_all();
    for (auto& t : pool) {
      t.join();
    }
  }

  ~thread_pool() {
    exit();
  }

};

class tokenizer {
  std::vector<std::string> tokens;
  static std::string empty;

  void tokenize_internal(std::stringstream& buffer, char delimiter) {
    std::string token;

    while (std::getline(buffer, token, delimiter)) {
      tokens.push_back(token);
    }
  }

 public:

  void tokenize(std::string&& str, char delimiter) {
    std::stringstream buffer(str);

    tokenize_internal(buffer, delimiter);
  }

  void tokenize(std::string& str, char delimiter) {
    std::stringstream buffer(str);

    tokenize_internal(buffer, delimiter);
  }

  tokenizer() = default;

  tokenizer(std::string&& str, char delimiter) {
    tokenize(str, delimiter);
  }

  tokenizer(std::string& str, char delimiter) {
    tokenize(str, delimiter);
  }

  size_t count() {
    return tokens.size();
  }

  std::vector<std::string>& get_tokens() {
    return tokens;
  }

  std::string& get_token(std::string::size_type i) {
    return i < tokens.size() ? tokens[i] : empty;
  };

  void reset() {
    tokens.clear();
  }
};

std::string tokenizer::empty{""};

class http_message {
  std::string version{"1.1"};
  std::string header;
  std::string body;
  std::string message;

  struct http_response_status {
    std::string code;
    std::string status;
  };

  static std::map<int, http_response_status> http_response_statuses;

  void set_statusline(int status = 200) {
    header += std::string{"HTTP/"} + version + std::string{" "}
              + http_response_statuses[status].code + std::string{" "}
              + http_response_statuses[status].status + std::string{"\r\n"};
  }

 public:

  http_message(int status = 200, const std::string& _version = "1.1")
    : version{const_cast<std::string&>(_version)}, header{""}, body{""} {
    set_statusline(status);
    message = header + std::string{"\r\n"} + body;
  }

  http_message(std::string& body_, int status = 200,
               const std::string& _version = "1.1")
               : version{_version}, header{""}, body{body_} {
    set_statusline(status);
    message = header + std::string{"\r\n"} + body;
  }

  void add_header(std::string& key, std::string& value) {
    if (key.length() > 0) {
      header += key + std::string{": "} + value + std::string{"\r\n"};

      message = header + std::string{"\r\n"} + body;
    }
  }

  void add_header(std::string&& key, std::string&& value) {
    if (key.length() > 0) {
      header += key + std::string{": "} + value + std::string{"\r\n"};

      message = header + std::string{"\r\n"} + body;
    }
  }

  void add_header(std::string& key, std::initializer_list<std::string> values) {
    if (key.length() > 0) {
      header += key + std::string{": "};
      for (auto v : values) {
        header += v + std::string{","};
      }
      header += std::string{"\r\n"};

      message = header + std::string{"\r\n"} + body;
    }
  }

  void add_header(std::string&& key,
                  std::initializer_list<std::string> values) {
    if (key.length() > 0) {
      header += key + std::string{": "};
      for (auto v : values) {
        header += v + std::string{";"};
      }
      header += std::string{"\r\n"};

      message = header + std::string{"\r\n"} + body;
    }
  }

  void add_body(std::string& _body) {
    body = _body;
    message = header + std::string{"\r\n"} + body;
  }

  void add_body(std::string&& _body) {
    body = _body;
    message = header + std::string{"\r\n"} + body;
  }

  std::string& content() {
    return message;
  }
};

std::map<int, http_message::http_response_status>
http_message::http_response_statuses = {
  { 200, { std::string{"200"}, std::string("OK") } },
  { 201, { std::string{"201"}, std::string("Created") } },
  { 302, { std::string{"302"}, std::string("Found") } },
  { 400, { std::string{"400"}, std::string("Bad Request") } },
  { 401, { std::string{"401"}, std::string("Unauthorized") } },
  { 403, { std::string{"403"}, std::string("Forbidden") } },
  { 404, { std::string{"404"}, std::string("Not Found") } },
  { 405, { std::string{"405"}, std::string("Method Not Allowed") } },
  { 500, { std::string{"500"}, std::string("Internal Server Error") } },
};

class http_client {
  int client_fd{-1};
  std::string host{};
  unsigned int port{};
  std::string directory{};

 public:
  http_client(int client_fd_, std::string& host_, unsigned int port_,
              const std::string& directory_ = "") : client_fd(client_fd_),
    host(host_), port(port_), directory(directory_) {
  }

  ~http_client() {
    /* Redundant but safe */
    close(client_fd);
  }

  friend std::ostream& operator<<(std::ostream& o, const http_client& c) {
    o << c.host << ":" << c.port;
    return o;
  }

  void operator()() {
    constexpr auto buffer_size = 8192;
    unsigned char buffer[buffer_size];
    ssize_t nbytes = recv(client_fd, buffer, buffer_size, 0);
    if (nbytes < 0) {
      std::cerr << "Failed to recv from client\n";
      close(client_fd);
      return;
    }

    // Parser HTTP request
    tokenizer t{std::string{reinterpret_cast<const char*>(buffer),
                            static_cast<std::string::size_type>(nbytes)}, '\r'};
    // Get the start-line
    std::string reqline{t.get_token(0)};
    // Get headers
    std::vector<std::string> headers{};
    int i;
    for (i = 1; i < t.count(); i++) {
      auto& token = t.get_token(i);
      if (token == "\n") {
        break;
      }
      headers.push_back(token);
    }
    // Get request body
    std::string body{};
    if (i < t.count() - 1) {
      // note the offset of 1 to skip the '\n' character
      body = std::string{t.get_token(++i), 1};
    }
    // Get the requested path and method
    t.reset();
    t.tokenize(reqline, ' ');
    // Get request method
    std::string method{t.get_token(0)};
    // Get request path
    std::string path{t.get_token(1)};

    std::cout << "Requested path: " << path << '\n';

    // Build HTTP response
    http_message *response = nullptr;
    do {
      if (method != "GET" && method != "POST") {
        response = new http_message(405);
        break;
      }

      if (path == "/") {
        response = new http_message;
        break;

      } else if (path.find("echo") == 1) {
        t.reset();
        t.tokenize(path, '/');
        std::string arg{path.substr(path.find(t.get_token(2)))};

        response = new http_message;

#if __cplusplus >= 201703L
        auto it = std::find_if(
            headers.begin(),
            headers.end(),
            [](std::string& h) {
              return h.find("Accept-Encoding") != std::string::npos;
            }
          );
#else
        auto it = headers.begin();
        while (it != headers.end()) {
          if (it->find("Accept-Encoding") != std::string::npos) {
            break;
          }
          ++it;
        }
#endif

        do {
          if (it != headers.end()) {
          	t.reset();
          	t.tokenize(*it, ':');
          	if (t.count() != 2) {
          	  break;
          	}
          	std::string &enc_tok = t.get_token(1);

				  	std::vector<std::pair<std::string, std::string>> encodings;

            /* werkzeug v2.2.2, file: werkzeug/http.py */
			    	std::regex accept_re(
			    	    R"(()"
			    	      R"([^\s;,]+)"
			    	      R"((?:[ \t]*;[ \t]*)"
			    	        R"((?:)"
			    	          R"([^\s;,q][^\s;,]*)"
			    	        R"(|)"
			    	          R"(q[^\s;,=][^\s;,]*)"
			    	        R"())"
			    	      R"()*)"
			    	    R"())"
			    	    R"((?:[ \t]*;[ \t]*q=)"
			    	      R"((\d*(?:\.\d+)?))"
			    	      R"([^,]*)"
			    	    R"()?)"
			    	  );
				  	std::smatch match;
				  	std::string::const_iterator start(enc_tok.cbegin());
				  	while (std::regex_search(start, enc_tok.cend(), match, accept_re)) {
				  		std::string encoding = match[1].matched ? match[1].str()
				  				: match[4].str();
				  		std::string qvalue = match[2].matched ? match[2].str() : "1.0";

				  		encodings.push_back({encoding, qvalue});

				  	  start = match.suffix().first;
				  	}
				  	if (encodings.empty()) {
				  		break;
          	}

				  	/* Choose gzip if available */
#if __cplusplus >= 201703L && 1
            auto enc_it = std::find_if(
              encodings.begin(),
              encodings.end(),
              [](std::pair<std::string, std::string> &p) {
                return p.first.find("gzip") != std::string::npos;
              }
            );
#else
            auto enc_it = encodings.begin();
            while (enc_it != encodings.end()) {
              if (enc_it->first.find("gzip") != std::string::npos) {
                break;
              }
              ++enc_it;
            }
#endif
            if (enc_it == encodings.end()) {
              break;
            }
				  	std::string &accept_encoding = enc_it->first;
            if (accept_encoding != "gzip") {
              break;
            }

				  	response->add_header("Content-Encoding", "gzip");
				  }
        } while (0);

        response->add_header("Content-Type", "text/plain");
        response->add_header("Content-Length", std::to_string(arg.length()));
        response->add_body(arg);
        break;

      } else if (path.find("files") == 1) {
        if (directory.length() == 0) {
          break;
        }

        t.reset();
        t.tokenize(path, '/');
        std::string filename{path.substr(path.find(t.get_token(2)))};
        std::string filepath = directory + std::string{"/"} + filename;

        // Host files from directory
        if (method == "GET") {
          struct stat stbuf;
          if ( (stat(filepath.c_str(), &stbuf) != 0) && (errno == ENOENT) ) {
            break;
          }

          char data[stbuf.st_size] = { 0, };
          int fd = open(filepath.c_str(), O_RDONLY);
          if (fd < 0) {
            response = new http_message(500);
            break;
          }

          ssize_t nread = read(fd, data, stbuf.st_size);
          close(fd);
          if (nread != stbuf.st_size) {
            response = new http_message(500);
            break;
          }

          response = new http_message;
          response->add_header("Content-Type", "application/octet-stream");
          std::string arg = std::string{"filename=\""} + filename
                            + std::string{"\""};
          response->add_header("Content-Disposition",  { "attachment", arg });
          response->add_header("Content-Length", std::to_string(nread));
          response->add_body(
            std::string{data, static_cast<std::string::size_type>(nread)}
          );
          break;

        } else if (method == "POST") {
          int fd = open(filepath.c_str(),
                        O_WRONLY | O_CREAT | O_SYNC,
                        S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH);
          if (fd < 0) {
            response = new http_message(500);
            break;
          }
          ssize_t nwrite = write(fd, body.c_str(), body.length());
          close(fd);
          if (nwrite != body.length()) {
            response = new http_message(500);
            break;
          }

          response = new http_message(201);
          break;

        }

      } else if (path == "/user-agent") {
#if __cplusplus >= 201703L && 1
        auto it = std::find_if(
            headers.begin(),
            headers.end(),
            [](std::string& h) {
              return h.find("User-Agent") != std::string::npos;
            }
          );
#else
        auto it = headers.begin();
        while (it != headers.end()) {
          if (it->find("User-Agent") != std::string::npos) {
            break;
          }
          ++it;
        }
#endif
        if (it == headers.end()) {
          break;
        }
        t.reset();
        t.tokenize(*it, ' ');
        if (t.count() != 2) {
          break;
        }
        std::string useragent = t.get_token(1);

        response = new http_message;
        response->add_header("Content-Type", "text/plain");
        response->add_header("Content-Length",
                             std::to_string(useragent.length()));
        response->add_body(useragent);
        break;
      }
    } while (0);

    // Default response
    if (!response) {
      response = new http_message(404);
    }
    if (!response) {
      std::cerr << "Failed to create HTTP response\n";
      close(client_fd);
      return;
    }
    std::string respstr{response->content()};
    delete response;

    // Send HTTP response
    nbytes = send(client_fd, respstr.c_str(), respstr.length(), 0);
    if (nbytes < 0) {
      std::cerr << "Failed to send to client\n";
    }

    close(client_fd);
  }
};

class http_server {
  int server_fd;
  std::string directory;

 public:

  http_server(const std::string& host, unsigned int port,
              const std::string& directory_ = "", unsigned int backlog = 5)
              : directory(directory_) {
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    const char* port_str = std::to_string(port).c_str();
    const char *node_str = host == "" ? NULL : host.c_str();

    int status;
    /* Get address(es) to bind the socket to */
    if ((status = getaddrinfo(node_str, port_str, &hints, &res)) != 0) {
      std::string error_message = "socket() failed: ";
      error_message += gai_strerror(status);
      error_message += '\n';
      throw std::runtime_error(error_message);
    }

    status = -1;
    /* Try each address until we successfully bind the socket */
    for (struct addrinfo *rp = res; rp != NULL; rp = rp->ai_next) {
      sockaddr_in *inet_addr = (struct sockaddr_in*)res->ai_addr;
      std::cout << "Trying address " << inet_ntoa(inet_addr->sin_addr) << ":" <<
                ntohs(inet_addr->sin_port) << "\n";

      /* Create a socket */
      server_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
      if (server_fd == -1) {
        std::string error_message = "socket() failed: ";
        error_message += strerror(errno);
        error_message += '\n';
        std::cerr << error_message;
        continue;
      }

      // Since the tester restarts your program quite often, setting REUSE_PORT
      // ensures that we don't run into 'Address already in use' errors
      int reuse = 1;
      if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &reuse,
                     sizeof(reuse)) < 0) {
        close(server_fd);
        std::string error_message = "setsockopt() failed: ";
        error_message += strerror(errno);
        error_message += '\n';
        std::cerr << error_message;
        continue;
      }

      /* Bind the socket to current address */
      if (bind(server_fd, res->ai_addr, res->ai_addrlen) == -1) {
        close(server_fd);
        std::string error_message = "bind() failed: ";
        error_message += strerror(errno);
        error_message += '\n';
        std::cerr << error_message;
      } else {
        /* Success! */
        sockaddr_in *inet_addr = (struct sockaddr_in*)res->ai_addr;
        std::cout << "Bound to address " << inet_ntoa(inet_addr->sin_addr) <<
                  ":" << ntohs(inet_addr->sin_port) << "\n";

        status = 0;
        break;
      }
    }

    freeaddrinfo(res);

    if (status != -1) {
      /* Set the socket as listening */
      if (listen(server_fd, (backlog == 0 ? SOMAXCONN : backlog)) == -1) {
        close(server_fd);
        std::string error_message = "listen() failed: ";
        error_message += strerror(errno);
        error_message += '\n';
        throw std::runtime_error(error_message);
      }
    } else {
      throw std::runtime_error("Could not create server");
    }
  }

  ~http_server() {
    close(server_fd);
  }

  http_client* accept() {
    struct sockaddr_in client_addr;
    int client_addr_len = sizeof(client_addr);

    int client_fd = ::accept(server_fd, (struct sockaddr *) &client_addr,
                             (socklen_t *) &client_addr_len);
    if (client_fd < 0) {
      std::cerr << "accept() failed: " << strerror(errno) << '\n';
      return nullptr;
    }

    char ipaddr_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr.sin_addr), ipaddr_str, INET_ADDRSTRLEN);
    std::string ipaddr = ipaddr_str;
    unsigned int port = ntohs(client_addr.sin_port);

    return new http_client(client_fd, ipaddr, port, directory);
  }

};

std::string get_directory(int argc, char **argv) {
  int opt;
  std::string directory{};

  struct option long_options[] = {
    {"directory", required_argument, 0, 'd'},
    {0, 0, 0, 0}
  };
  while ((opt = getopt_long(argc, argv, "d:", long_options, NULL)) != -1) {
    switch (opt) {
      case 'd':
        directory = std::string(optarg);
        break;
      case '?':
        return "";
    }
  }

  return directory;
}

int main(int argc, char **argv) {

  setup_sigint_handler();

  http_server server("127.0.0.1", 4221, get_directory(argc, argv));

  std::cout << "Waiting for a client to connect...\n";

  thread_pool<http_client, 10> tpool;

  while (!exit_condition) {
    if (tpool.size() < 10) {
      http_client *c = server.accept();;
      if (!c) {
        continue;
      }

      std::cout << "Client " << *c << " connected\n";

      tpool.enqueue(c);
    }
  }

  tpool.exit();
  
  std::cout << "Exiting\n";

  return EXIT_SUCCESS;
}
