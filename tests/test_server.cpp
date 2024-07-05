#include <iostream>
#include <thread>
#include <chrono>
#include <mutex>
#include <memory>
#include <vector>
#include <string>
#include <cstring>
#include <fcntl.h>
#include <curl/curl.h>
#include <sys/wait.h>

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define NUM_THREADS 8
#define NUM_REQUESTS 64

std::mutex mtx;

bool do_exec(const std::string& command, std::string& output) {
  int stdout_pipe[2], stderr_pipe[2];
  if (pipe(stdout_pipe) < 0 || pipe(stderr_pipe) < 0) {
    perror("pipe");
    return false;
  }

  pid_t pid = fork();
  if (pid < 0) {
    perror("fork");
    return false;
  }

  if (pid == 0) {
    // Redirect stdout and stderr to pipes
    dup2(stdout_pipe[1], STDOUT_FILENO);
    dup2(stderr_pipe[1], STDERR_FILENO);

    // Close unused ends of the pipes
    close(stdout_pipe[0]);
    close(stdout_pipe[1]);
    close(stderr_pipe[0]);
    close(stderr_pipe[1]);

    std::vector<char*> args;
    char* token = strtok(const_cast<char*>(command.c_str()), " ");
    while (token != nullptr) {
      args.push_back(token);
      token = strtok(nullptr, " ");
    }
    args.push_back(nullptr);

    execvp(args[0], args.data());
    // execvp only returns if an error occurs
    perror("execvp");
    _exit(EXIT_FAILURE);
  } else {
    // Close write ends of the pipes
    close(stdout_pipe[1]);
    close(stderr_pipe[1]);

    char buffer[4096];
    ssize_t count;

    while ((count = read(stdout_pipe[0], buffer, sizeof(buffer))) > 0) {
      output.append(buffer, count);
    }
    std::cout << __func__ << ": output: " << output << '\n';

    while ((count = read(stderr_pipe[0], buffer, sizeof(buffer))) > 0) {
      output.append(buffer, count);
    }
    std::cout << __func__ << ": output: " << output << '\n';

    // Close read ends of the pipes
    close(stdout_pipe[0]);
    close(stderr_pipe[0]);

    // Wait for the child process to complete
    int status;
    waitpid(pid, &status, 0);

    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
  }

  return false;
}

int diff(std::string& f1, std::string& f2) {
  std::string command = "diff " + f1 + " " + f2 + " 2>&1";
  char result[8];

  std::shared_ptr<FILE> diff_proc(popen(command.c_str(), "r"), pclose);
  if (!diff_proc) {
    std::cerr << "Error executing command(" << command << "): "
      << strerror(errno) << '\n';
    return EXIT_FAILURE;
  }

  if (fgets(result, sizeof(result), diff_proc.get()) == nullptr) {
    return 0;
  } else {
    return 1;
  }
  
  //std::string output;
  //do_exec(command, output);
  //if (output.empty()) {
  //  return 0;
  //} else {
  //  return 1;
  //}
}

size_t write_callback(void* contents, size_t size, size_t nmemb,
                      std::string* response) {
  size_t total_size = size * nmemb;
  response->append((char*)contents, total_size);
  return total_size;
}

int main(int argc, char** argv) {
  std::string uploadfile{};

  if (argc == 3 &&
      !strncmp(argv[1], "--file", strlen("--directory"))) {
    uploadfile = std::string(argv[2]);
  } else {
    std::cerr << "Provide upload file using --file\n";
    return EXIT_FAILURE;
  }

  unsigned char buf[4096];
  int fd = open(uploadfile.c_str(), O_RDONLY);
  if (fd < 0) {
    return EXIT_FAILURE;
  }
  ssize_t nread = read(fd, buf, 4096);
  close(fd);

  curl_global_init(CURL_GLOBAL_ALL);
  std::thread* threads[NUM_THREADS];

  int nrequest = 0;

  for (int i = 0; i < NUM_THREADS; i++) {
    threads[i] = new std::thread(
      [&uploadfile, &nrequest, buf, nread]() {

        int num_requests_per_thread = NUM_REQUESTS / NUM_THREADS;
        for (int j = 0; j < num_requests_per_thread; j++) {
          pid_t tid = gettid();
          std::string newfilename{"newfile" + std::to_string(tid)};

          std::unique_lock<std::mutex> lock(mtx);
          int nreqlocal = ++nrequest;
          lock.unlock();

          CURL* curl = curl_easy_init();

          std::string url{};

          switch (nreqlocal % 5) {
            case 0:
              url = "http://localhost:4221";
              break;

            case 1:
              url = "http://localhost:4221/echo/mangoes/in/summer";
              break;

            case 2:
              url = "http://localhost:4221/user-agent";
              break;

            case 3:
              url = "http://localhost:4221/files/testfile";
              break;

            case 4:
              url += "http://localhost:4221/files/" + newfilename;
          }

          struct curl_slist *headers = nullptr;
          std::string response;

          curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
          curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
          curl_easy_setopt(curl, CURLOPT_USERAGENT, "laggybrowser/0.01");
          curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
          curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

          if (nreqlocal % 5 == 4) {
            curl_slist_append(headers,
                              "Content-Type: application/octet-stream");
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, buf);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, nread);
          }

          CURLcode res = curl_easy_perform(curl);

          if (nreqlocal % 5 == 4) {
            curl_slist_free_all(headers);
            headers = nullptr;

            if (res == CURLE_OK) {
            }
          }

          if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " <<
                      curl_easy_strerror(res) << std::endl;
          } else {
            long http_response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_response_code);

            std::lock_guard<std::mutex> lock(mtx);

            std::cout << "Request # " << nreqlocal << " URL: " << url;

            if (nreqlocal % 5 == 4) {
              std::string newfile =
                std::string{uploadfile, 0, uploadfile.rfind("/") + 1}
                + newfilename;

              if (diff(uploadfile, newfile)) {
                std::cout << ANSI_COLOR_RED " Files don't match" ANSI_COLOR_RESET;
              } else {
                std::cout << ANSI_COLOR_GREEN " Files match" ANSI_COLOR_RESET;
              }

              if (!newfile.empty()) {
                if (unlink(newfile.c_str())) {
                  std::cerr << "\nError removing file(" << newfile << "): "
                    << strerror(errno) << '\n';
                }
              }

            }

            std::cout << " Response code: " << http_response_code;

            if (nreqlocal % 5 == 3 || nreqlocal % 5 == 4) {
              std::cout  << " Response length: " << response.length()
                << std::endl;

            } else {
              std::cout << " Response: " << response << std::endl;
            }
          }

          curl_easy_cleanup(curl);
        }

    });
  }

  for (int i = 0; i < NUM_THREADS; i++) {
    threads[i]->join();
    delete threads[i];
  }

  curl_global_cleanup();

  return 0;
}
