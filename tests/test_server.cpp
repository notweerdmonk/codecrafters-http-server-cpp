#include <iostream>
#include <thread>
#include <chrono>
#include <mutex>
#include <string>
#include <cstring>
#include <fcntl.h>
#include <curl/curl.h>

#define NUM_THREADS 5
#define NUM_REQUESTS 50

size_t write_callback(void* contents, size_t size, size_t nmemb,
          std::string* response) {
  size_t total_size = size * nmemb;
  response->append((char*)contents, total_size);
  return total_size;
}

std::mutex cout_mutex;

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
          std::unique_lock<std::mutex> lock(cout_mutex);
          std::cout << "nrequest: " << ++nrequest << " j: " << j << '\n';
          lock.unlock();

          CURL* curl = curl_easy_init();

          std::string url{};

          switch (nrequest % 5) {
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
              url = "http://localhost:4221/files/newfile";
          }

          struct curl_slist *headers = nullptr;
          std::string response;

          curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
          curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
          curl_easy_setopt(curl, CURLOPT_USERAGENT, "laggybrowser/0.01");
          curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
          curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

          if (nrequest % 5 == 4) {
            curl_slist_append(headers,
                "Content-Type: application/octet-stream");
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, buf);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, nread);
          }

          CURLcode res = curl_easy_perform(curl);
          //std::this_thread::sleep_for(std::chrono::milliseconds(200));
          if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
          } else {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << "Request # " << nrequest << " URL: " << url <<
                  " Response: " << response << std::endl;
          }

          if (nrequest % 5 == 4) {
            curl_slist_free_all(headers);
            headers = nullptr;
          }
          curl_easy_cleanup(curl);
        }

      }
    );
  }

  for (int i = 0; i < NUM_THREADS; i++) {
    threads[i]->join();
    delete threads[i];
  }

  curl_global_cleanup();

  return 0;
}
