#pragma once
#include <QSettings>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>
#include <QStringList>
#include <QFileDialog>
#include <QMessageBox>
#include <QDir>
#include <QWidget>

// Snapshot / restore all Dynam-managed QSettings keys to/from a JSON file.
// Lets the user keep distinct "profiles" — Home, Work, Travel — each with
// its own bypass technique, tunnel endpoint, Tor toggle, theme, etc.
//
// All file I/O lives in this header so MainWindow only has to call the
// two static methods.
namespace Profiles {

// Keys we round-trip. Limiting the set (rather than dumping every
// QSettings key) keeps profiles forward-compatible: new GUI-internal
// settings won't accidentally end up in a profile file.
inline QStringList managedKeys() {
    return {
        "ui/theme",
        "ui/auto_connect",
        "ui/log_retention",
        "network/bypass_technique",
        "network/tunnel_endpoint",
        "network/tor_enabled",
        "license/server_url",
    };
}

// Show a Save-As dialog and write the current QSettings snapshot to JSON.
inline void saveAs(QWidget* parent) {
    const QString suggested = QDir::homePath()
        + "/.dynam/profile.json";
    QDir().mkpath(QDir::homePath() + "/.dynam");
    const QString path = QFileDialog::getSaveFileName(
        parent, QObject::tr("Save profile"), suggested,
        QObject::tr("Dynam profile (*.json);;All files (*)"));
    if (path.isEmpty()) return;

    QJsonObject obj;
    QSettings s;
    for (const QString& k : managedKeys()) {
        obj.insert(k, QJsonValue::fromVariant(s.value(k)));
    }
    QJsonDocument doc(obj);
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        QMessageBox::warning(parent, QObject::tr("Save failed"), f.errorString());
        return;
    }
    f.write(doc.toJson(QJsonDocument::Indented));
}

// Show an Open dialog, load JSON, apply each key back to QSettings.
// Returns true if anything was applied — caller may want to re-apply
// theme or trigger a reconnect.
inline bool load(QWidget* parent) {
    const QString path = QFileDialog::getOpenFileName(
        parent, QObject::tr("Load profile"),
        QDir::homePath() + "/.dynam",
        QObject::tr("Dynam profile (*.json);;All files (*)"));
    if (path.isEmpty()) return false;

    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        QMessageBox::warning(parent, QObject::tr("Load failed"), f.errorString());
        return false;
    }
    const QJsonObject obj = QJsonDocument::fromJson(f.readAll()).object();
    if (obj.isEmpty()) {
        QMessageBox::warning(parent, QObject::tr("Load failed"),
                              QObject::tr("File is empty or not a valid profile."));
        return false;
    }

    QSettings s;
    int applied = 0;
    for (const QString& k : managedKeys()) {
        if (obj.contains(k)) {
            s.setValue(k, obj.value(k).toVariant());
            ++applied;
        }
    }
    QMessageBox::information(parent, QObject::tr("Profile loaded"),
        QObject::tr("Applied %1 setting%2 from %3.")
            .arg(applied).arg(applied == 1 ? "" : "s").arg(path));
    return applied > 0;
}

}  // namespace Profiles
