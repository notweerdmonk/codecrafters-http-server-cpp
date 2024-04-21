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
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

class tokenizer {
  std::vector<std::string> tokens;
  static std::string empty;

  public:

  void tokenize_internal(std::stringstream& buffer, char delimiter) {
    std::string token;

    while (std::getline(buffer, token, delimiter)) {
      tokens.push_back(token);
    }
  }

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
  
  void set_statusline() {
    header += std::string{"HTTP/"} + version + std::string{" "}
    + http_response_statuses[200].code + std::string{" "}
    + http_response_statuses[200].status + std::string{"\r\n"};
  }

  void set_statusline(int status) {
    header += std::string{"HTTP/"} + version + std::string{" "}
    + http_response_statuses[status].code + std::string{" "}
    + http_response_statuses[status].status + std::string{"\r\n"};
  }

  public:

  http_message() : header{""}, body{""} {
    set_statusline();
    message = header + std::string{"\r\n"} + body;
  }

  http_message(int status) {
    set_statusline(status);
    message = header + std::string{"\r\n"} + body;
  }

  http_message(std::string& _version, int status = 200)
    : version{_version}, header{""}, body{""} {
    set_statusline(status);
    message = header + std::string{"\r\n"} + body;
  }

  http_message(std::string& _version, std::string& _body, int status = 200)
    : version{_version}, header{""}, body{_body} {
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

  void add_body(std::string& body) {
    message = header + std::string{"\r\n"} + body;
  }

  void add_body(std::string&& body) {
    message = header + std::string{"\r\n"} + body;
  }

  std::string& content() {
    return message;
  }
};

std::map<int, http_message::http_response_status>
http_message::http_response_statuses = {
  { 200, { std::string{"200"}, std::string("OK") } },
  { 302, { std::string{"302"}, std::string("Found") } },
  { 400, { std::string{"400"}, std::string("Bad Request") } },
  { 401, { std::string{"401"}, std::string("Unauthorized") } },
  { 403, { std::string{"403"}, std::string("Forbidden") } },
  { 404, { std::string{"404"}, std::string("Not Found") } },
  { 405, { std::string{"405"}, std::string("Method Not Allowed") } },
  { 500, { std::string{"500"}, std::string("Internal Server Error") } },
};

std::string directory{""};

void handle_client(int client_fd) {
  unsigned char buffer[1024];
  ssize_t nbytes = recv(client_fd, buffer, 1024, 0);
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
  std::vector<std::string> headers;
  for (int i = 1; i < t.count(); i++) {
    auto& token = t.get_token(i);
    if (token == "\n") {
      break;
    }
    headers.push_back(token);
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
    if (method != "GET") {
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
      struct stat stbuf;
      if ( (stat(filepath.c_str(), &stbuf) != 0) && (errno == ENOENT) ) {
        break;
      }

      char data[stbuf.st_size] = { 0, };
      int fd = open(filepath.c_str(), O_RDONLY);
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

    } else if (path == "/user-agent") {
#if __cplusplus >= 201703L
      auto it = std::find_if(headers.begin(),
                             headers.end(),
                             [](std::string& h) {
                               return h.find("User-Agent") != std::string::npos;
                             });
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
      std::cout << "User agent: " << useragent << '\n';

      response = new http_message;
      response->add_header("Content-Type", "text/plain");
      response->add_header("Content-Length", std::to_string(useragent.length()));
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

static
std::atomic<bool> exit_condition = false;

static
struct sigaction old_sa;

void sigint_handler(int sig) {
  sigaction(SIGINT, &old_sa, NULL);

  exit_condition = true;

  sigaction(SIGINT, &old_sa, NULL);
}

int main(int argc, char **argv) {
  // Setup SIGINT handler
  struct sigaction sa;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = sigint_handler;
  sigaction(SIGINT, &sa, &old_sa);

  // Host files from directory
  if (argc == 3) {
    if (!strncmp(argv[1], "--directory", strlen("--directory"))) {
      directory = std::string{argv[2]};
    }
  }

  // You can use print statements as follows for debugging, they'll be visible when running tests.
  std::cout << "Logs from your program will appear here!\n";

  // Uncomment this block to pass the first stage
  //
  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
    std::cerr << "Failed to create server socket\n";
    return 1;
  }
  //
  // Since the tester restarts your program quite often, setting REUSE_PORT
  // ensures that we don't run into 'Address already in use' errors
  int reuse = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
    std::cerr << "setsockopt failed\n";
    return 1;
  }
  //
  struct sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(4221);
  
  if (bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) != 0) {
    std::cerr << "Failed to bind to port 4221\n";
    return 1;
  }
  
  int connection_backlog = 5;
  if (listen(server_fd, connection_backlog) != 0) {
    std::cerr << "listen failed\n";
    return 1;
  }
  
  struct sockaddr_in client_addr;
  int client_addr_len = sizeof(client_addr);
  
  std::cout << "Waiting for a client to connect...\n";
  
  // Handle connections
  constexpr auto max_concurrent_conn = 5;
  std::thread tclient[max_concurrent_conn];
  int num_conn = 0;

  while ( !exit_condition && (num_conn < max_concurrent_conn) ) {
    int client_fd = accept(server_fd, (struct sockaddr *) &client_addr, (socklen_t *) &client_addr_len);
    if (client_fd < 0) {
      std::cerr << "Failed to accept client\n";
      continue;
    }
    std::cout << "Client connected\n";

    tclient[num_conn++] = std::thread(handle_client, client_fd);
  }

  for (int i = 0; i < num_conn; i++) {
    tclient[i].join();
  }

cleanup:
  close(server_fd);

  return 0;
}
