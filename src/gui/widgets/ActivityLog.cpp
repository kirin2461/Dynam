#include "ActivityLog.hpp"

#include <QPlainTextEdit>
#include <QVBoxLayout>
#include <QLabel>

ActivityLog::ActivityLog(QWidget* parent) : QWidget(parent) {
    auto* lay = new QVBoxLayout(this);
    lay->addWidget(new QLabel(QStringLiteral("<b>Журнал активности</b>"), this));
    edit_ = new QPlainTextEdit(this);
    edit_->setReadOnly(true);
    edit_->setMaximumBlockCount(1000);
    edit_->setStyleSheet(
        "QPlainTextEdit{background:#101018;color:#c0c0d0;font-family:Consolas,monospace;"
        "font-size:11px;border:1px solid #2a2a3a;}");
    lay->addWidget(edit_, 1);
}

void ActivityLog::appendLine(const QString& line) {
    edit_->appendPlainText(line);
}

void ActivityLog::setLogs(const std::vector<std::string>& logs) {
    edit_->clear();
    for (const auto& l : logs) edit_->appendPlainText(QString::fromStdString(l));
}
