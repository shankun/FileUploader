//
// Created by SK on 2023-2-27.
//

#include <boost/asio.hpp>
#include <iostream>
#include <string>
#include <functional>
#include <thread>
#include <chrono>
#include "./third_party/cxxopts/include/cxxopts.hpp"
#include "sender_dialog.h"
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

SenderDialog::SenderDialog()
: m_uploadButton("上传"),
  m_fileButton("选择文件"),
  m_hostLabel("IP地址:"),
  m_portLabel("端口号:"),
  m_keyLabel("密钥:"),
  m_fileLabel("文件路径:"),
  m_threadsLabel("线程数:"),
  m_sizeLabel("切片大小:")
{
  set_title("上传文件");
  set_default_size(370, 300);
  //gtk_window_set_position(GTK_WINDOW (window), GTK_WIN_POS_CENTER); // deprecated
  set_resizable(false);
  m_grid.set_margin(12);
  set_child(m_grid);

  activate();
}

SenderDialog::~SenderDialog()
{
}

/// \brief file_button's callback function, select file
// 当gtkmm 升到 4.10，换用Gtk::FileDialog
void SenderDialog::select_file() {
  if (!m_pFileDlg) {
    m_pFileDlg = std::make_unique<Gtk::FileChooserDialog>(
            "选择文件", Gtk::FileChooser::Action::OPEN);
    m_pFileDlg->set_transient_for(*this);
    m_pFileDlg->set_modal(true);
    m_pFileDlg->signal_response().connect(sigc::bind(
      sigc::mem_fun(*this, &SenderDialog::on_file_dialog_response), m_pFileDlg.get()));

    //Add response buttons to the dialog:
    m_pFileDlg->add_button("取消", Gtk::ResponseType::CANCEL);
    m_pFileDlg->add_button("打开", Gtk::ResponseType::OK);

    //Add filters, so that only certain file types can be selected:
    auto filter_any = Gtk::FileFilter::create();
    filter_any->set_name("所有文件");
    filter_any->add_pattern("*");
    m_pFileDlg->add_filter(filter_any);
  }
  //Show the dialog and wait for a user response:
  m_pFileDlg->set_visible();
}

void SenderDialog::on_file_dialog_response(int response_id, Gtk::FileChooserDialog* dialog)
{
  //Handle the response:
  switch (response_id)
  {
    case Gtk::ResponseType::OK:
    {
      // Notice that this is a std::string, not a Glib::ustring.
      m_fileEntry.set_text(dialog->get_file()->get_path());
      break;
    }
    case Gtk::ResponseType::CANCEL:
    case Gtk::ResponseType::CLOSE:
    {
      std::cout << "未选择要上传的文件" << std::endl;
      break;
    }
    default:
    {
      std::cout << "Unexpected button clicked." << std::endl;
      break;
    }
  }
  m_pFileDlg->set_visible(false);
}

/// \brief m_uploadButton's callback function, do upload
void SenderDialog::upload() {
  //time start
  std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();

  std::string filename(m_fileEntry.get_text());
  std::string host(m_hostEntry.get_text());
  std::string key(m_keyEntry.get_text());
  int port = std::strtol(m_portEntry.get_text().c_str(), nullptr, 10);
  int thread = std::strtol(m_threadsEntry.get_text().c_str(), nullptr, 10);
  int size = std::strtol(m_sizeEntry.get_text().c_str(), nullptr, 10);

  std::regex ip_regex(
  "^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$|^([\\da-fA-F]{1,4}:){6}((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$|^::([\\da-fA-F]{1,4}:){0,4}((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$|^([\\da-fA-F]{1,4}:):([\\da-fA-F]{1,4}:){0,3}((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$|^([\\da-fA-F]{1,4}:){2}:([\\da-fA-F]{1,4}:){0,2}((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$|^([\\da-fA-F]{1,4}:){3}:([\\da-fA-F]{1,4}:){0,1}((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$|^([\\da-fA-F]{1,4}:){4}:((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$|^([\\da-fA-F]{1,4}:){7}[\\da-fA-F]{1,4}$|^:((:[\\da-fA-F]{1,4}){1,6}|:)$|^[\\da-fA-F]{1,4}:((:[\\da-fA-F]{1,4}){1,5}|:)$|^([\\da-fA-F]{1,4}:){2}((:[\\da-fA-F]{1,4}){1,4}|:)$|^([\\da-fA-F]{1,4}:){3}((:[\\da-fA-F]{1,4}){1,3}|:)$|^([\\da-fA-F]{1,4}:){4}((:[\\da-fA-F]{1,4}){1,2}|:)$|^([\\da-fA-F]{1,4}:){5}:([\\da-fA-F]{1,4})?$|^([\\da-fA-F]{1,4}:){6}:$"
      );

  if (filename.empty() or host.empty() or key.empty()) {
    prompt_result("参数错误", "文件路径、IP地址或密钥不能为空！");
    return;
  }

  if (port == 0 or thread == 0 or size == 0) {
    prompt_result("参数错误", "端口号、线程数和切片大小必须是正整数！");
    return;
  }

  if (!std::regex_match(host,ip_regex)) {
    prompt_result("参数错误", "IP地址格式错误！");
    return;
  }

  if (port > 65536 or port < 0) {
    prompt_result("参数错误", "端口号必须在0到65536之间！");
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
    prompt_result("错误信息", "上传失败！", Gtk::MessageType::ERROR);
    return;
  }

  // get time info
  auto t2 = std::chrono::steady_clock::now();
  std::chrono::duration<double> time_span =
      std::chrono::duration_cast<std::chrono::duration<double>>(t2 - now);

  std::string info = "上传成功，用时";
  info.append(std::to_string(time_span.count()));
  info.append("秒。");
  prompt_result("提示信息", info.c_str());
}

void SenderDialog::prompt_result(const Glib::ustring& title, const Glib::ustring& content, 
                                 Gtk::MessageType msg_type)
{
  m_pMsgDlg.reset(new Gtk::MessageDialog(*this, content, false, msg_type));
  m_pMsgDlg->set_modal(true);
  m_pMsgDlg->set_hide_on_close(true);
  m_pMsgDlg->set_title(title);

  m_pMsgDlg->signal_response().connect(
       sigc::hide(sigc::mem_fun(*m_pMsgDlg, &Gtk::Widget::hide)));

  m_pMsgDlg->show();
}

void SenderDialog::activate() {
  m_threadsEntry.set_text("1");
  m_sizeEntry.set_text("65536");

  m_fileLabel.set_halign(Gtk::Align::END);
  m_hostLabel.set_halign(Gtk::Align::END);
  m_portLabel.set_halign(Gtk::Align::END);
  m_keyLabel.set_halign(Gtk::Align::END);
  m_threadsLabel.set_halign(Gtk::Align::END);
  m_sizeLabel.set_halign(Gtk::Align::END);

  m_grid.attach(m_fileLabel, 0, 0, 1, 1);
  m_grid.attach_next_to(m_fileEntry, m_fileLabel, Gtk::PositionType::RIGHT);
  m_grid.attach_next_to(m_fileButton, m_fileEntry, Gtk::PositionType::RIGHT);
  m_grid.attach(m_hostLabel, 0, 1, 1, 1);
  m_grid.attach(m_hostEntry, 1, 1, 2, 1);
  m_grid.attach(m_portLabel, 0, 2, 1, 1);
  m_grid.attach(m_portEntry, 1, 2, 2, 1);
  m_grid.attach(m_keyLabel, 0, 3, 1, 1);
  m_grid.attach(m_keyEntry, 1, 3, 2, 1);
  m_grid.attach(m_threadsLabel, 0, 4, 1, 1);
  m_grid.attach(m_threadsEntry, 1, 4, 2, 1);
  m_grid.attach(m_sizeLabel, 0, 5, 1, 1);
  m_grid.attach(m_sizeEntry, 1, 5, 2, 1);
  m_grid.attach(m_separator, 0, 6, 3, 1);
  m_grid.attach(m_uploadButton, 1, 7);
  m_grid.set_column_spacing(10);
  m_grid.set_row_spacing(10);

  m_fileButton.signal_clicked().connect(
    sigc::mem_fun(*this, &SenderDialog::select_file));

  //link callback function upload to m_uploadButton
  m_uploadButton.signal_clicked().connect(
    sigc::mem_fun(*this, &SenderDialog::upload));

  // g_signal_connect_swapped(m_uploadButton,
  //                           "clicked",
  //                           G_CALLBACK(gtk_widget_destroy),
  //                           window);

  // Make the button the default widget
  set_default_widget(m_fileButton);
}

int main(int argc, char* argv[]) {
  // iostream与当前环境中的locale无关
  Glib::set_init_to_users_preferred_locale(false);
  auto app = Gtk::Application::create("org.gtkmm.fileuploader");

  // Shows the window and returns when it is closed.
  return app->make_window_and_run<SenderDialog>(argc, argv);
}