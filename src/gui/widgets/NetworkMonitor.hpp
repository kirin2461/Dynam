#pragma once
#include <QWidget>
#include <QLabel>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QHeaderView>
#include <QVBoxLayout>
#include <QNetworkInterface>
#include <QHostAddress>

class NetworkMonitor : public QWidget {
    Q_OBJECT
public:
    explicit NetworkMonitor(QWidget* parent = nullptr) : QWidget(parent) {
        auto* layout = new QVBoxLayout(this);
        layout->setContentsMargins(0, 0, 0, 0);

        layout->addWidget(new QLabel("<b>Network Interfaces</b>", this));

        tree_ = new QTreeWidget(this);
        tree_->setHeaderLabels({"Interface", "Address", "State"});
        tree_->setRootIsDecorated(false);
        tree_->setAlternatingRowColors(true);
        tree_->header()->setStretchLastSection(true);
        layout->addWidget(tree_);

        refresh();
    }

    // Re-enumerate. Called by MainWindow's networkTimer on a tick — Qt caches
    // interface info, so this is cheap (microseconds), not a syscall.
    void refresh() {
        if (!tree_) return;
        tree_->clear();

        const auto ifaces = QNetworkInterface::allInterfaces();
        for (const QNetworkInterface& iface : ifaces) {
            // Skip loopback and inactive interfaces — they're noise here.
            const auto flags = iface.flags();
            if (flags.testFlag(QNetworkInterface::IsLoopBack)) continue;
            if (!flags.testFlag(QNetworkInterface::IsUp))      continue;

            QString primaryIp;
            for (const QNetworkAddressEntry& entry : iface.addressEntries()) {
                if (entry.ip().protocol() == QAbstractSocket::IPv4Protocol) {
                    primaryIp = entry.ip().toString();
                    break;
                }
            }
            if (primaryIp.isEmpty()) continue;

            const QString state = flags.testFlag(QNetworkInterface::IsRunning)
                                      ? "running" : "up";
            auto* item = new QTreeWidgetItem(tree_,
                {iface.humanReadableName(), primaryIp, state});
            tree_->addTopLevelItem(item);
        }
        tree_->resizeColumnToContents(0);
        tree_->resizeColumnToContents(1);
    }

private:
    QTreeWidget* tree_ = nullptr;
};
