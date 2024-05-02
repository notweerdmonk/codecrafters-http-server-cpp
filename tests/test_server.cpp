#include <iostream>
#include <thread>
#include <chrono>
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
  curl_global_init(CURL_GLOBAL_ALL);
  std::thread* threads[NUM_THREADS];

  int nrequest = 0;

  for (int i = 0; i < NUM_THREADS; i++) {
    threads[i] = new std::thread(
      [i, &nrequest]() {
        int num_requests_per_thread = NUM_REQUESTS / NUM_THREADS;
        for (int j = 0; j < num_requests_per_thread; j++) {
          CURL* curl = curl_easy_init();

          std::string url{};

          switch (nrequest % 4) {
            case 0:
              url = "http://localhost:4221";
              break;

            case 1:
              url = "http://localhost:4221/echo/pwned/in/dream";
              break;

            case 2:
              url = "http://localhost:4221/user-agent";
              break;

            case 3:
              url = "http://localhost:4221/files/testfile";
          }

          std::string response;

          curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
          curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
          curl_easy_setopt(curl, CURLOPT_USERAGENT, "laggybrowser1337");
          curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
          curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

          CURLcode res = curl_easy_perform(curl);
          //std::this_thread::sleep_for(std::chrono::milliseconds(200));
          if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
          } else {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << "Request # " << ++nrequest << " URL: " << url <<
                  " Response: " << response << std::endl;
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
