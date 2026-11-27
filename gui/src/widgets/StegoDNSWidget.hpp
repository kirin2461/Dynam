#pragma once
#include <QWidget>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QPlainTextEdit>

namespace widgets {
class StegoDNSWidget : public QWidget {
    Q_OBJECT
public:
    explicit StegoDNSWidget(QWidget* parent = nullptr);
signals:
    void encodeRequested(const QString& data, const QString& passphrase);
    void decodeRequested(const QString& record, const QString& passphrase);
public slots:
    void showEncoded(const QString& spfRecord);
    void showDecoded(const QJsonObject& params);
private:
    void setupUi();
    QLineEdit* m_passphraseEdit;
    QPlainTextEdit* m_inputEdit;
    QPlainTextEdit* m_outputEdit;
    QPushButton* m_encodeBtn;
    QPushButton* m_decodeBtn;
};
} // namespace widgets
