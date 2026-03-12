// sample.cpp – exercise file for cish-scanner

#include <memory>
#include <cstdio>

namespace MyApp {

class Widget {
public:
    Widget() : data_(new int[64]) {}  // new inside constructor

    void render() {
        printf("rendering\n");        // no_printf hit
        // TODO: use a real renderer  // todo_comment hit
        int* raw = new int(42);       // no_raw_new hit
    }

    void safe_render() {
        auto p = std::make_unique<int>(42); // fine
    }

private:
    int* data_;
};

class Engine {
public:
    void run() {
        Widget w;
        w.render();
        // FIXME: handle errors      // todo_comment hit
    }
};

namespace Detail {
    void helper() {
        goto done;   // no_goto hit
        done:;
    }
}

} // namespace MyApp

// top-level function
void standalone() {
    printf("hello\n");   // no_printf hit (no scope filter → any named scope)
}

namespace Danger {

class ResourceManager {
public:
    void cleanup() {
        // TODO: replace with RAII
        // delete raw_ptr_;
        // free(buffer_);
        do_cleanup();
    }

private:
    void do_cleanup() { /* implementation */ }
};

} // namespace Danger
