struct client_data {
  http_client *c;
  std::unique_ptr<std::thread> pt;

  client_data() : c(nullptr), pt(nullptr) {

  }
};

template<size_t max_size = 8>
class queue {
  client_data* data[max_size];
  ssize_t front, rear;

  public:

  queue() : front(-1), rear(-1) {
  }

  bool is_empty() {
    return front == -1;
  }

  bool is_full() {
    return rear == max_size - 1;
  }

  size_t size() {
    return is_empty() ? 0 : rear - front + 1;
  }

  void enqueue(client_data *p) {
    if (is_full()) {
      return;
    }

    data[++rear] = p;

    if (is_empty()) {
      front = 0;
    }
  }

  client_data* peek() {
    if (is_empty()) {
      return nullptr;
    }

    return data[front];
  }

  client_data* dequeue() {
    if (is_empty()) {
      return nullptr;
    }

    client_data* p = data[front++];

    if (front > rear) {
      front = rear = -1;
    }

    return p;
  }

    // Iterator class for queue

#if __cplusplus >= 202002L

    class iterator {
        client_data** ptr;

    public:
        using iterator_category = std::forward_iterator_tag;
        using value_type = client_data*;
        using difference_type = ssize_t;
        using pointer = client_data**;
        using reference = client_data*&;

        iterator(client_data** p) : ptr(p) {}

        iterator& operator++() {
            ++ptr;
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
        return iterator(&data[front + 1]);
    }

    iterator end() {
        return iterator(&data[rear + 1]);
    }

#else

  class iterator : public std::iterator<std::forward_iterator_tag, client_data*> {
    client_data** ptr;

    public:
    iterator(client_data** p) : ptr(p) {}

    iterator& operator++() {
      ++ptr;
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

    client_data*& operator*() const {
      return *ptr;
    }

    client_data** operator->() const {
      return ptr;
    }
  };

  iterator begin() {
    return iterator(&data[front + 1]);
  }

  iterator end() {
    return iterator(&data[rear + 1]);
  }

#endif

};

