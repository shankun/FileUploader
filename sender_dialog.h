#include <gtkmm.h>

class SenderDialog : public Gtk::Window
{
public:
  SenderDialog();
  virtual ~SenderDialog();

  void prompt_result(const Glib::ustring& title, 
                     const Glib::ustring& content, 
    Gtk::MessageType msg_type = Gtk::MessageType::INFO);

private:
  void activate();
  void upload();

  // Signal handlers:
  void select_file();
  void on_file_dialog_response(int response_id, Gtk::FileChooserDialog* dialog);

  // Child widgets:
  Gtk::Grid m_grid;
  Gtk::Label m_hostLabel;
  Gtk::Label m_portLabel;
  Gtk::Label m_keyLabel;
  Gtk::Label m_fileLabel;
  Gtk::Label m_threadsLabel;
  Gtk::Label m_sizeLabel;
  Gtk::Button m_fileButton;
  Gtk::Button m_uploadButton;
  Gtk::Entry m_fileEntry;
  Gtk::Entry m_hostEntry;
  Gtk::Entry m_portEntry;
  Gtk::Entry m_keyEntry;
  Gtk::Entry m_threadsEntry;
  Gtk::Entry m_sizeEntry;
  Gtk::Separator m_separator;

  std::unique_ptr<Gtk::MessageDialog> m_pMsgDlg;
};
