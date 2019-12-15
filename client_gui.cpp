//
// Created by LD on 2019-12-15.
//

#include <gtk/gtk.h>
#include <boost/asio.hpp>
#include <string>
#include <functional>
#include <thread>
#include <chrono>

#include "./third_party/cxxopts/include/cxxopts.hpp"

#include "file.h"
#include "protocol.h"

INITIALIZE_EASYLOGGINGPP

/// \file client.cpp
/// \brief Client Implementation
/// \note
/** Workflow
 * Client: Server Hello
 * Server: Client Hello
 * Client: File Negotiation
 * Server: File Negotiation
 * Client: Start Transfering file
 * Cilent: Finish Transfering file
 * Server: Close file and clean
 */

using boost::asio::ip::tcp;
using boost::asio::buffer;

/// \class Uploader
/// \brief Class to perform upload work
/// \detail after created Uploader will handle all negotiation work
///         and start required threads to upload data to the server
/// \datamember std::string ip
///             ip of the server
/// \datamember int port
///             port of the server
/// \datamember tcp::socket socket_
///             tcp socket of the server
/// \datamember protocol::AESEncrypter enc
///             encrypter object
/// \datamember protocol::AESDecrypter dec
///             decrypter object
/// \datamember std::string session
///             session id of this connection
/// \datamember int piece_size
///             transfer file piece size
/// \datamember std::string file_name
///             file name (and path)
/// \datamember file::file_reader f
///             file reader object
/// \datamember int ths
///             threads count
class Uploader : public std::enable_shared_from_this<Uploader> {
 private:
  std::string ip;
  int port;
  tcp::socket socket_;
  protocol::AESEncrypter enc;
  protocol::AESDecrypter dec;
  std::string session;
  int piece_size;
  std::string file_name;
  file::file_reader f;
  int ths;
 public:
  // transfer thread function.
  // for access convenience, make it friend function
  friend void transfer(Uploader *ul);
  /// \brief constructor
  /// \note this constructor simply initialize its members. for detailed
  ///       infomation, see class's datamenber explanation.
  explicit Uploader(
      std::string &_ip,
      int &_port,
      tcp::socket &sock,
      protocol::AESEncrypter &_enc,
      protocol::AESDecrypter &_dec,
      std::string &_file_name,
      int &_piece_size,
      int &thread_number) :
      ip(_ip),
      port(_port),
      // socket is the established connection between the client and server
      // therefore can not be copied. use std::move to move the socket
      socket_(std::move(sock)),
      // copy the encrypter and decrypter
      enc(_enc),
      dec(_dec),
      file_name(_file_name),
      piece_size(_piece_size),
      f(file_name, piece_size),
      ths(thread_number) {
    // force send small tcp packet to make protocol negotiation
    // works properly
    boost::asio::ip::tcp::no_delay option(true);
    socket_.set_option(option);
  }
  /// \brief encapsulate boost::asio read function
  /// \detail encapsulate the boost::asio's read function and reduce parameter
  ///         count to make the function signature the same as read_msg series
  ///         functions' parameter's function
  /// \param length how many bytes will the function read
  /// \return received data
  std::string _read(int length) {
    std::string _tmp;
    // resize string to actually make let boost::asio::buffer get the length
    // info.
    // reserve didn't change string length so buffer will see it as 0 length
    // buffer and can  not receive anything
    _tmp.resize(length);
    read(socket_, buffer(_tmp), boost::asio::transfer_exactly(length));
    return _tmp;
  };
  /// \brief handshake period logic.
  void handshake() {
    //Client: Server hello
    socket_.write_some(buffer(protocol::build_msg(protocol::server_hello_build(
        enc))));

    //Client: Verify client hello

    //wrap the scope for function to call for data
    try {
      // use std::bind to convert member functino to functor object to pass it
      // to external function to call
      std::function<std::string(int)>
          _t = std::bind(&Uploader::_read, this, std::placeholders::_1);
      int status =
          protocol::client_hello_verify(dec, protocol::read_msg(_t), session);
      if (status != 0) {
        exit(1);
      }
    }
    catch (const std::exception &e) {
      e.what();
      exit(1);
    }
  }
  /// \brief negotiation period logic.
  void file_negotiation() {

    //convert file path to file name.
    std::string t(file_name);
    std::replace(t.begin(), t.end(), '\\', '/');
    std::string filename = t.substr(t.find_last_of('/')+1);

    //Client: Send negotiate message
    socket_.write_some(buffer(protocol::build_msg(
        protocol::file_negotiation_build(enc,
                                         session,
                                         piece_size,
                                         f.get_size(),
                                         filename)
    )));

    //Client: Check negotiate response
    try {
      std::function<std::string(int)>
          _t = std::bind(&Uploader::_read, this, std::placeholders::_1);
      int status = protocol::file_negotiation_finish(dec,
                                                     protocol::read_msg(_t),
                                                     session);
      if (status != 0) {
        exit(1);
      }
    }
    catch (const std::exception &e) {
      e.what();
      exit(1);
    }
  }
  /// \brief transfer period logic.
  /// \note Versus server, even using asio to do asynchorous programming,
  ///         we decided to make client send data to server synchorous,
  ///         because it's difficult to control concurrent number in
  ///         asynchorous code.
#ifndef _MSC_VER
  // This code can not compile on MSVC but compile and works fine on G++
  void file_transfer() {
    // thread pointers array
    std::thread *threads[ths];
    // set all to nullptr
    for (int i = 0; i < ths; ++i) {
      threads[i] = nullptr;
    }
    for (int i = 0; i < ths; ++i) {
      // start new threads
      // use lambda function to encapsulate transfer task
      threads[i] = new std::thread([this]() { transfer(this); });
    }
    // join the threads (after task finished, thread can be joined)
    for (auto t : threads) {
      if (t && t->joinable()) {
        t->join();
        // then the pointer is useless
        delete t;
      }
    }
    // here threads is a stack object so can be deleted automaticly
  }
#else
  void file_transfer() {
    // MSVC see ths as variable so we must make it heap object
//    auto threads = new std::thread * [ths];
    // update: use smart pointer to hold heap object to make sure it
    // can be deleted
    std::unique_ptr<std::thread *[]> threads(new std::thread * [ths]);
    for (int i = 0; i < ths; ++i) {
      threads[i] = new std::thread([this]() {transfer(this); });
    }
    for (int i = 0; i < ths; ++i) {
      if (threads[i]->joinable()) {
        threads[i]->join();
        delete threads[i];
      }
    }
//    // and delete it
//    delete[] threads;
  // since we used smart pointer, the object will automaticly be deleted
  // after left the scope due to RAII even when exception throwed
  }
#endif
};

/// \brief file transfer worker.
/// \param ul pointer to negotiated Uploader object
void transfer(Uploader *ul) {

  // transfer threads use different io_context
  boost::asio::io_context io_context;
  tcp::socket sock(io_context);

  // Encrypter / Decrypter object is not thread safe so we need to
  // copy it for each thread
  protocol::AESEncrypter enc(ul->enc);
  protocol::AESDecrypter dec(ul->dec);

  // connect to the server and configure socket
  boost::asio::ip::tcp::endpoint
      ep(boost::asio::ip::address::from_string(ul->ip), ul->port);

  sock.connect(ep);

  boost::system::error_code error;

  std::string _sess = ul->session;

  // file transfer init

  boost::asio::write(sock,
                     buffer(protocol::build_msg_transfer(
                         protocol::file_transfer_init(
                             enc,
                             ul->session))),
                     error);

//  std::function<std::string(int)>
//      _t = std::bind(&Uploader::_read, ul, std::placeholders::_1);
//
//  if (protocol::file_transfer_init_confirm(
//      dec, protocol::read_msg_transfer(_t)) != 0) {
//    LOG(WARNING) << "Server encountered error.";
//  }

  int size;

  // we have to use heap memory and char pointer now.
  // TODO: Update file module to support smart pointer
  char *_read_buf = new char[ul->piece_size];

  // make memory release even if error occured.
  try {
    do {
      std::uintmax_t _offset;

      size = ul->f.read(_read_buf, _offset);

      // give length info to string constructor
      // to prevent construct stop at first 0x00 byte
      std::string _read_str(_read_buf, ul->piece_size);

      boost::asio::write(sock,
                         buffer(protocol::build_msg_transfer(
                             protocol::file_transfer_build(
                                 enc,
                                 _sess,
                                 _offset / ul->piece_size,
                                 size,
                                 _read_str))),
                         error);

//    try {
//      std::function<std::string(int)>
//          _t = std::bind(&Uploader::_read, ul, std::placeholders::_1);
//      int status = protocol::file_transfer_confirm(
//          dec, protocol::read_msg_transfer(_t), ul->session);
//      if (status != 0) {
//        exit(1);
//      }
//    }
//    catch (const std::exception &e) {
//      e.what();
//      exit(1);
//    }
      // reset memory in case error happened
      memset(_read_buf, 0, ul->piece_size);
    } while (size != 0);

    // send finish packet
    boost::asio::write(sock, buffer(protocol::build_msg_transfer(
        protocol::file_transfer_build(enc, _sess, 0, 0, " "))), error);
  }
  catch (std::exception &e) {
    LOG(ERROR) << e.what();
    // remember to delete _read_buf
    delete[] _read_buf;
    return;
  }
  delete[] _read_buf;
}

struct widgets {
  GtkEntry *file_entry;
  GtkEntry *host_entry;
  GtkEntry *port_entry;
  GtkEntry *key_entry;
  GtkEntry *thread_entry;
  GtkEntry *size_entry;
  GtkWidget *ul_button;
} d;

/// \brief file_button's callback function, select file
void select_file(GtkWidget *widget, gpointer *data) {
  GtkFileChooserNative *file_chooser;
  GtkFileChooserAction action = GTK_FILE_CHOOSER_ACTION_OPEN;
  gint res;
  GtkEntry *entry = (GtkEntry *) data;

  file_chooser = gtk_file_chooser_native_new("Open File",
                                             NULL, action, "Open", "Cancel"
  );
  res = gtk_native_dialog_run(GTK_NATIVE_DIALOG(file_chooser));
  if (res == GTK_RESPONSE_ACCEPT) {
    char *filename;
    GtkFileChooser *chooser = GTK_FILE_CHOOSER(file_chooser);
    filename = gtk_file_chooser_get_filename(chooser);
    gtk_entry_set_text(entry, filename);
  }
}

/// \brief ul_button's callback function, do upload
void upload(GtkWidget *widget, gpointer *data) {

  //time start
  std::chrono::steady_clock::time_point  now = std::chrono::steady_clock::now();

  widgets *d = (widgets *) data;
  gtk_widget_set_sensitive(d->ul_button, FALSE);
  const char *_filename = gtk_entry_get_text(d->file_entry);
  const char *_host = gtk_entry_get_text(d->host_entry);
  const char *_port = gtk_entry_get_text(d->port_entry);
  const char *_key = gtk_entry_get_text(d->key_entry);
  const char *_thread = gtk_entry_get_text(d->thread_entry);
  const char *_size = gtk_entry_get_text(d->size_entry);

  std::string filename(_filename);
  std::string host(_host);
  std::string key(_key);
  int port = std::strtol(_port, nullptr, 10);
  int thread = std::strtol(_thread, nullptr, 10);
  int size = std::strtol(_size, nullptr, 10);

  std::regex ip_regex(
  "^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$|^([\\da-fA-F]{1,4}:){6}((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$|^::([\\da-fA-F]{1,4}:){0,4}((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$|^([\\da-fA-F]{1,4}:):([\\da-fA-F]{1,4}:){0,3}((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$|^([\\da-fA-F]{1,4}:){2}:([\\da-fA-F]{1,4}:){0,2}((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$|^([\\da-fA-F]{1,4}:){3}:([\\da-fA-F]{1,4}:){0,1}((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$|^([\\da-fA-F]{1,4}:){4}:((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$|^([\\da-fA-F]{1,4}:){7}[\\da-fA-F]{1,4}$|^:((:[\\da-fA-F]{1,4}){1,6}|:)$|^[\\da-fA-F]{1,4}:((:[\\da-fA-F]{1,4}){1,5}|:)$|^([\\da-fA-F]{1,4}:){2}((:[\\da-fA-F]{1,4}){1,4}|:)$|^([\\da-fA-F]{1,4}:){3}((:[\\da-fA-F]{1,4}){1,3}|:)$|^([\\da-fA-F]{1,4}:){4}((:[\\da-fA-F]{1,4}){1,2}|:)$|^([\\da-fA-F]{1,4}:){5}:([\\da-fA-F]{1,4})?$|^([\\da-fA-F]{1,4}:){6}:$"
      );

  if (filename.empty() or host.empty() or key.empty()) {
    GtkWidget *error_dialog;
    error_dialog = gtk_message_dialog_new(NULL,
                                          GTK_DIALOG_MODAL,
                                          GTK_MESSAGE_INFO,
                                          GTK_BUTTONS_OK,
                                          "File name or IP or Key must not be empty!"
    );
    gtk_window_set_title(GTK_WINDOW (error_dialog), "Error");
    gtk_dialog_run(GTK_DIALOG(error_dialog));
    gtk_widget_destroy(error_dialog);
    return;
  }

  if (port == 0 or thread == 0 or size == 0) {
    GtkWidget *error_dialog;
    error_dialog = gtk_message_dialog_new(NULL,
                                          GTK_DIALOG_MODAL,
                                          GTK_MESSAGE_INFO,
                                          GTK_BUTTONS_OK,
                                          "Port or Thread or Size must be a number > 0!"
    );
    gtk_window_set_title(GTK_WINDOW (error_dialog), "Error");
    gtk_dialog_run(GTK_DIALOG(error_dialog));
    gtk_widget_destroy(error_dialog);
    return;
  }

  if (!std::regex_match(host,ip_regex)) {
    GtkWidget *error_dialog;
    error_dialog = gtk_message_dialog_new(NULL,
                                          GTK_DIALOG_MODAL,
                                          GTK_MESSAGE_INFO,
                                          GTK_BUTTONS_OK,
                                          "Wrong IP address!"
    );
    gtk_window_set_title(GTK_WINDOW (error_dialog), "Error");
    gtk_dialog_run(GTK_DIALOG(error_dialog));
    gtk_widget_destroy(error_dialog);
    return;
  }

  if (port > 65536 or port < 0) {
    GtkWidget *error_dialog;
    error_dialog = gtk_message_dialog_new(NULL,
                                          GTK_DIALOG_MODAL,
                                          GTK_MESSAGE_INFO,
                                          GTK_BUTTONS_OK,
                                          "Port must between 0 and 65536!"
    );
    gtk_window_set_title(GTK_WINDOW (error_dialog), "Error");
    gtk_dialog_run(GTK_DIALOG(error_dialog));
    gtk_widget_destroy(error_dialog);
    return;
  }

  try {
    el::Configurations defaultConf;
    defaultConf.setToDefault();
    defaultConf.setGlobally(
        el::ConfigurationType::Format, "[%datetime - %level]: %msg");
    el::Loggers::reconfigureLogger("default", defaultConf);
    // On windows, to use BSD sockets these steps are required.
    #ifdef WIN32
    protocol::init_environment();
    #endif

    protocol::AESEncrypter enc(key);
    protocol::AESDecrypter dec(key);

    // main thread io_context
    boost::asio::io_context io_context;
    tcp::socket sock(io_context);

    boost::asio::ip::tcp::endpoint
        ep(boost::asio::ip::address::from_string(host), port);

    sock.connect(ep);

    Uploader ul(host, port, sock, enc, dec, filename, size, thread);
    ul.handshake();

    ul.file_negotiation();

    ul.file_transfer();

    io_context.run();

    #ifdef WIN32
    protocol::clear_environment();
    #endif
  }catch (...){
    #ifdef WIN32
    protocol::clear_environment();
    #endif
    GtkWidget *error_dialog;
    error_dialog = gtk_message_dialog_new(NULL,
                                          GTK_DIALOG_MODAL,
                                          GTK_MESSAGE_INFO,
                                          GTK_BUTTONS_OK,
                                          "Upload fail!"
    );
    gtk_window_set_title(GTK_WINDOW (error_dialog), "Error");
    gtk_dialog_run(GTK_DIALOG(error_dialog));
    gtk_widget_destroy(error_dialog);
    return;
  }

  // get time info
  auto t2 = std::chrono::steady_clock::now();
  std::chrono::duration<double> time_span =
      std::chrono::duration_cast<std::chrono::duration<double>>(t2 - now);

  std::string info = "Upload finished using ";
  info.append(std::to_string(time_span.count()));
  info.append("seconds.");

  GtkWidget *message_dialog;
  message_dialog = gtk_message_dialog_new(NULL,
                                          GTK_DIALOG_MODAL, GTK_MESSAGE_INFO,
                                          GTK_BUTTONS_OK, info.c_str()
  );
  gtk_window_set_title(GTK_WINDOW (message_dialog), "Information");
  gtk_dialog_run(GTK_DIALOG(message_dialog));
  gtk_widget_destroy(message_dialog);
}

void activate(GtkApplication *app, gpointer user_data) {
  GtkWidget *window;

  GtkWidget *grid;

  GtkWidget *ul_button;
  GtkWidget *file_button;

  GtkWidget *host_label;
  GtkWidget *port_label;
  GtkWidget *key_label;
  GtkWidget *file_label;
  GtkWidget *thread_label;
  GtkWidget *size_label;

  GtkWidget *host_entry;
  GtkWidget *port_entry;
  GtkWidget *key_entry;
  GtkWidget *file_entry;
  GtkWidget *thread_entry;
  GtkWidget *size_entry;

  //create window object
  window = gtk_application_window_new(app);
  //set window title
  gtk_window_set_title(GTK_WINDOW (window), "FileUploader");
  //set window size
  gtk_window_set_default_size(GTK_WINDOW (window), 250, 200);
  gtk_window_set_position(GTK_WINDOW (window), GTK_WIN_POS_CENTER);
  gtk_window_set_resizable(GTK_WINDOW (window), FALSE);

  //create grid object
  grid = gtk_grid_new();
  gtk_container_set_border_width(GTK_CONTAINER(grid), 10);
  gtk_container_add(GTK_CONTAINER(window), grid);

  //create label object
  host_label = gtk_label_new("IP:");
  port_label = gtk_label_new("Port:");
  key_label = gtk_label_new("Key:");
  file_label = gtk_label_new("File name:");
  thread_label = gtk_label_new("Thread:");
  size_label = gtk_label_new("Size:");

  //create entry object
  host_entry = gtk_entry_new();
  port_entry = gtk_entry_new();
  key_entry = gtk_entry_new();
  file_entry = gtk_entry_new();
  thread_entry = gtk_entry_new();
  size_entry = gtk_entry_new();

  //set entry text for default value
  gtk_entry_set_text(GTK_ENTRY(thread_entry), "1");
  gtk_entry_set_text(GTK_ENTRY(size_entry), "65536");

  //gtk_widget_set_sensitive(thread_entry, FALSE);

  d.file_entry = GTK_ENTRY(file_entry);
  d.host_entry = GTK_ENTRY(host_entry);
  d.port_entry = GTK_ENTRY(port_entry);
  d.key_entry = GTK_ENTRY(key_entry);
  d.thread_entry = GTK_ENTRY(thread_entry);
  d.size_entry = GTK_ENTRY(size_entry);

  //create button object
  ul_button = gtk_button_new_with_label("Upload");
  //link callback function upload to ul_button
  g_signal_connect(ul_button, "clicked", G_CALLBACK(upload), (gpointer) &d);
  g_signal_connect_swapped (ul_button,
                            "clicked",
                            G_CALLBACK(gtk_widget_destroy),
                            window);

  file_button = gtk_button_new_with_label("Select file");
  g_signal_connect(file_button,
                   "clicked",
                   G_CALLBACK(select_file),
                   file_entry);

  d.ul_button = ul_button;

  //put entry and label into grid
  gtk_grid_attach(GTK_GRID(grid), file_label, 0, 0, 1, 1);
  gtk_grid_attach(GTK_GRID(grid), file_entry, 1, 0, 1, 1);
  gtk_grid_attach(GTK_GRID(grid), file_button, 2, 0, 1, 1);
  gtk_grid_attach(GTK_GRID(grid), host_label, 0, 1, 1, 1);
  gtk_grid_attach(GTK_GRID(grid), host_entry, 1, 1, 2, 1);
  gtk_grid_attach(GTK_GRID(grid), port_label, 0, 2, 1, 1);
  gtk_grid_attach(GTK_GRID(grid), port_entry, 1, 2, 2, 1);
  gtk_grid_attach(GTK_GRID(grid), key_label, 0, 3, 1, 1);
  gtk_grid_attach(GTK_GRID(grid), key_entry, 1, 3, 2, 1);
  gtk_grid_attach(GTK_GRID(grid), thread_label, 0, 4, 1, 1);
  gtk_grid_attach(GTK_GRID(grid), thread_entry, 1, 4, 2, 1);
  gtk_grid_attach(GTK_GRID(grid), size_label, 0, 5, 1, 1);
  gtk_grid_attach(GTK_GRID(grid), size_entry, 1, 5, 2, 1);

  gtk_grid_attach(GTK_GRID(grid), ul_button, 0, 6, 3, 1);

  //show window
  gtk_widget_show_all(window);

}

int main(int argc, char **argv) {
  GtkApplication *app;
  int status;

  app = gtk_application_new("org.gtk.fileuploader", G_APPLICATION_FLAGS_NONE);
  g_signal_connect (app, "activate", G_CALLBACK(activate), NULL);
  status = g_application_run(G_APPLICATION (app), argc, argv);
  g_object_unref(app);

  return status;
}