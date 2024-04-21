#include <iostream>
#include <cstdlib>
#include <string>
#include <cstring>
#include <sstream>
#include <vector>
#include <map>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

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

int main(int argc, char **argv) {
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
  
  int client_fd = accept(server_fd, (struct sockaddr *) &client_addr, (socklen_t *) &client_addr_len);
  if (client_fd < 0) {
    std::cerr << "Failed to accept client\n";
    return 1;
  }
  std::cout << "Client connected\n";
  
  unsigned char buffer[1024];
  ssize_t nbytes = recv(client_fd, buffer, 1024, 0);
  if (nbytes < 0) {
    std::cerr << "Failed to recv from client\n";
    close(client_fd);
    return 1;
  }

  // Parser HTTP request
  tokenizer t{std::string{reinterpret_cast<const char*>(buffer),
                          static_cast<std::string::size_type>(nbytes)}, '\r'};
  // Get the start-line
  std::string reqline{t.get_token(0)};
  // Get headers
  std::vector<std::string> headers = t.get_tokens();
  for (int i = 0; i < t.count(); i++) {
    auto& token = t.get_token(i);
    if (token == "\n") {
      break;
    }
    headers.push_back(token);
  }

  t.reset();
  // Get the requested path
  t.tokenize(reqline, ' ');
  std::string path{t.get_token(1)};

  std::cout << "Requested path: " << path << '\n';

  // Build HTTP response
  http_message *response = nullptr;
  do {
    if (path == "/") {
      response = new http_message();
      break;
    } else if (path.find("echo") == 1) {
      t.reset();
      t.tokenize(path, '/');
      std::string arg{path.substr(path.find(t.get_token(2)))};

      response = new http_message();
      response->add_header("Content-Type", "text/plain");
      response->add_header("Content-Length", std::to_string(arg.length()));
      response->add_body(arg);
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

      response = new http_message();
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
    return 1;
  }
  std::string respstr{response->content()};
  delete response;

  // Send HTTP response
  nbytes = send(client_fd, respstr.c_str(), respstr.length(), 0);
  if (nbytes < 0) {
    std::cerr << "Failed to send to client\n";
    close(client_fd);
    return 1;
  }
  
cleanup:
  close(server_fd);

  return 0;
}
