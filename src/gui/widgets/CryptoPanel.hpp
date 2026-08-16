#pragma once
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QLabel>
#include <QPlainTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QComboBox>
#include <QGroupBox>
#include <QMessageBox>
#include <QClipboard>
#include <QApplication>
#include <QFont>
#include "../../core/include/ncp_crypto.hpp"
#include "../../core/include/ncp_secure_memory.hpp"

// Live playground for ncp::Crypto. Operations are run synchronously on the
// UI thread — libsodium calls finish in microseconds for inputs of any
// reasonable size, so there's no need for a worker.
class CryptoPanel : public QWidget {
    Q_OBJECT
public:
    explicit CryptoPanel(ncp::Crypto* crypto, QWidget* parent = nullptr)
        : QWidget(parent), crypto_(crypto) {
        auto* root = new QVBoxLayout(this);

        // ─── Symmetric encryption (ChaCha20-Poly1305) ────────────────────────
        auto* symBox = new QGroupBox(tr("Symmetric encryption (ChaCha20-Poly1305)"), this);
        auto* symLayout = new QVBoxLayout(symBox);
        auto* keyRow = new QHBoxLayout;
        keyEdit_ = new QLineEdit(symBox);
        keyEdit_->setPlaceholderText(tr("32-byte key, hex (64 chars). Click ‘Generate key’ to fill."));
        keyEdit_->setFont(mono());
        auto* keyBtn = new QPushButton(tr("Generate key"), symBox);
        keyRow->addWidget(new QLabel(tr("Key:"), symBox));
        keyRow->addWidget(keyEdit_, 1);
        keyRow->addWidget(keyBtn);

        plainEdit_ = new QPlainTextEdit(symBox);
        plainEdit_->setPlaceholderText(tr("Plaintext"));
        plainEdit_->setMaximumHeight(80);

        cipherEdit_ = new QPlainTextEdit(symBox);
        cipherEdit_->setPlaceholderText(tr("Ciphertext (hex). Wire format: [nonce:12][ct+tag]"));
        cipherEdit_->setFont(mono());
        cipherEdit_->setMaximumHeight(80);

        auto* btnRow = new QHBoxLayout;
        auto* encBtn = new QPushButton(tr("Encrypt →"), symBox);
        auto* decBtn = new QPushButton(tr("← Decrypt"), symBox);
        auto* copyCtBtn = new QPushButton(tr("Copy ciphertext"), symBox);
        btnRow->addWidget(encBtn);
        btnRow->addWidget(decBtn);
        btnRow->addStretch(1);
        btnRow->addWidget(copyCtBtn);

        symLayout->addLayout(keyRow);
        symLayout->addWidget(new QLabel(tr("Plaintext (UTF-8):"), symBox));
        symLayout->addWidget(plainEdit_);
        symLayout->addWidget(new QLabel(tr("Ciphertext (hex):"), symBox));
        symLayout->addWidget(cipherEdit_);
        symLayout->addLayout(btnRow);

        connect(keyBtn,   &QPushButton::clicked, this, &CryptoPanel::generateKey);
        connect(encBtn,   &QPushButton::clicked, this, &CryptoPanel::encryptText);
        connect(decBtn,   &QPushButton::clicked, this, &CryptoPanel::decryptText);
        connect(copyCtBtn,&QPushButton::clicked, this, [this]{
            QApplication::clipboard()->setText(cipherEdit_->toPlainText());
        });

        // ─── Hashing ─────────────────────────────────────────────────────────
        auto* hashBox = new QGroupBox(tr("Hash"), this);
        auto* hashLayout = new QVBoxLayout(hashBox);
        hashInput_ = new QPlainTextEdit(hashBox);
        hashInput_->setPlaceholderText(tr("Input (UTF-8)"));
        hashInput_->setMaximumHeight(60);
        auto* hashRow = new QHBoxLayout;
        hashAlgo_ = new QComboBox(hashBox);
        hashAlgo_->addItems({"SHA-256", "SHA-512", "BLAKE2b-256"});
        auto* hashBtn = new QPushButton(tr("Compute"), hashBox);
        hashOut_ = new QLineEdit(hashBox);
        hashOut_->setReadOnly(true);
        hashOut_->setFont(mono());
        hashRow->addWidget(new QLabel(tr("Algorithm:"), hashBox));
        hashRow->addWidget(hashAlgo_);
        hashRow->addWidget(hashBtn);
        hashLayout->addWidget(hashInput_);
        hashLayout->addLayout(hashRow);
        hashLayout->addWidget(hashOut_);
        connect(hashBtn, &QPushButton::clicked, this, &CryptoPanel::computeHash);

        // ─── Ed25519 keypair ─────────────────────────────────────────────────
        auto* edBox = new QGroupBox(tr("Generate Ed25519 keypair"), this);
        auto* edForm = new QFormLayout(edBox);
        edPub_ = new QLineEdit(edBox); edPub_->setReadOnly(true); edPub_->setFont(mono());
        edSec_ = new QLineEdit(edBox); edSec_->setReadOnly(true); edSec_->setFont(mono());
        auto* edBtn = new QPushButton(tr("Generate"), edBox);
        edForm->addRow(tr("Public:"), edPub_);
        edForm->addRow(tr("Secret:"), edSec_);
        edForm->addRow("", edBtn);
        connect(edBtn, &QPushButton::clicked, this, &CryptoPanel::generateEd25519);

        root->addWidget(symBox);
        root->addWidget(hashBox);
        root->addWidget(edBox);
        root->addStretch(1);
    }

private slots:
    void generateKey() {
        if (!crypto_) return;
        auto key = crypto_->generate_random(32);
        keyEdit_->setText(QString::fromStdString(ncp::Crypto::bytes_to_hex(key)));
    }

    void encryptText() {
        if (!crypto_) return;
        ncp::SecureMemory key;
        if (!hexToSecureMemory(keyEdit_->text(), 32, key)) {
            QMessageBox::warning(this, tr("Key error"),
                tr("Key must be 64 hex chars (32 bytes). Use ‘Generate key’."));
            return;
        }
        const QByteArray pt = plainEdit_->toPlainText().toUtf8();
        ncp::SecureMemory ptMem(reinterpret_cast<const uint8_t*>(pt.constData()),
                                 static_cast<size_t>(pt.size()));
        auto ct = crypto_->encrypt_chacha20(ptMem, key);
        if (ct.empty()) {
            QMessageBox::critical(this, tr("Encrypt failed"),
                tr("ChaCha20 encryption returned empty output."));
            return;
        }
        cipherEdit_->setPlainText(QString::fromStdString(ncp::Crypto::bytes_to_hex(ct)));
    }

    void decryptText() {
        if (!crypto_) return;
        ncp::SecureMemory key;
        if (!hexToSecureMemory(keyEdit_->text(), 32, key)) {
            QMessageBox::warning(this, tr("Key error"),
                tr("Key must be 64 hex chars (32 bytes)."));
            return;
        }
        ncp::SecureMemory ct;
        const QString ctHex = cipherEdit_->toPlainText().trimmed();
        if (!hexToSecureMemory(ctHex, 0, ct) || ct.size() < 28) {
            QMessageBox::warning(this, tr("Ciphertext error"),
                tr("Ciphertext hex is invalid or too short (need nonce+ct+tag)."));
            return;
        }
        auto pt = crypto_->decrypt_chacha20(ct, key);
        if (pt.empty()) {
            QMessageBox::critical(this, tr("Decrypt failed"),
                tr("Authentication failed — wrong key or corrupted ciphertext."));
            return;
        }
        plainEdit_->setPlainText(QString::fromUtf8(
            reinterpret_cast<const char*>(pt.data()),
            static_cast<int>(pt.size())));
    }

    void computeHash() {
        if (!crypto_) return;
        const QByteArray in = hashInput_->toPlainText().toUtf8();
        ncp::SecureMemory inMem(reinterpret_cast<const uint8_t*>(in.constData()),
                                 static_cast<size_t>(in.size()));
        ncp::SecureMemory out;
        switch (hashAlgo_->currentIndex()) {
            case 0: out = crypto_->hash_sha256(inMem); break;
            case 1: out = crypto_->hash_sha512(inMem); break;
            case 2: out = crypto_->hash_blake2b(inMem, 32); break;
        }
        hashOut_->setText(QString::fromStdString(ncp::Crypto::bytes_to_hex(out)));
    }

    void generateEd25519() {
        if (!crypto_) return;
        auto kp = crypto_->generate_keypair();
        edPub_->setText(QString::fromStdString(ncp::Crypto::bytes_to_hex(kp.public_key)));
        edSec_->setText(QString::fromStdString(ncp::Crypto::bytes_to_hex(kp.secret_key)));
    }

private:
    // Parse a hex string into SecureMemory. If expectedBytes is non-zero,
    // require exactly that length; pass 0 to accept any length.
    static bool hexToSecureMemory(const QString& hex, size_t expectedBytes,
                                   ncp::SecureMemory& out) {
        const QString clean = QString(hex).remove(' ').remove('\n').remove('\r');
        if (clean.size() % 2 != 0) return false;
        const size_t n = static_cast<size_t>(clean.size() / 2);
        if (expectedBytes != 0 && n != expectedBytes) return false;

        std::vector<uint8_t> buf;
        buf.reserve(n);
        for (int i = 0; i < clean.size(); i += 2) {
            bool ok = false;
            const uint8_t b = static_cast<uint8_t>(clean.mid(i, 2).toUInt(&ok, 16));
            if (!ok) return false;
            buf.push_back(b);
        }
        out = ncp::SecureMemory(buf.data(), buf.size());
        return true;
    }

    static QFont mono() {
        QFont f;
        f.setStyleHint(QFont::Monospace);
        f.setFamily("Menlo");
        return f;
    }

    ncp::Crypto* crypto_;  // not owned; lifetime = MainWindow

    QLineEdit*      keyEdit_;
    QPlainTextEdit* plainEdit_;
    QPlainTextEdit* cipherEdit_;

    QPlainTextEdit* hashInput_;
    QComboBox*      hashAlgo_;
    QLineEdit*      hashOut_;

    QLineEdit*      edPub_;
    QLineEdit*      edSec_;
};
