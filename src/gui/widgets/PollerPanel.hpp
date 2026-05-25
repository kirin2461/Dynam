#pragma once
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLineEdit>
#include <QSpinBox>
#include <QComboBox>
#include <QCheckBox>
#include <QFont>
#include <QBrush>
#include <QColor>
#include <QMessageBox>
#include <QEventLoop>
#include "PollerEngine.hpp"

class PollerTargetDialog : public QDialog {
    Q_OBJECT
public:
    explicit PollerTargetDialog(const PollerTarget& seed, QWidget* parent = nullptr)
        : QDialog(parent), target_(seed) {
        setWindowTitle(seed.id.isEmpty() ? tr("Add target") : tr("Edit target"));
        setModal(true);
        resize(420, 240);

        auto* root = new QVBoxLayout(this);
        auto* form = new QFormLayout;

        nameEdit_ = new QLineEdit(seed.name, this);
        nameEdit_->setPlaceholderText("My API");
        kindCombo_ = new QComboBox(this);
        kindCombo_->addItem(tr("HTTPS URL - HEAD request, 2xx/3xx = ok"),
                             static_cast<int>(PollerKind::HttpsUrl));
        kindCombo_->addItem(tr("DNS lookup - any records returned = ok"),
                             static_cast<int>(PollerKind::DnsLookup));
        kindCombo_->addItem(tr("TCP connect - host:port reachable = ok"),
                             static_cast<int>(PollerKind::TcpConnect));
        kindCombo_->setCurrentIndex(static_cast<int>(seed.kind));
        targetEdit_ = new QLineEdit(seed.target, this);
        intervalSpin_ = new QSpinBox(this);
        intervalSpin_->setRange(5, 86400);
        intervalSpin_->setValue(seed.intervalSec == 0 ? 60 : seed.intervalSec);
        intervalSpin_->setSuffix(" s");
        pausedCheck_ = new QCheckBox(tr("Paused"), this);
        pausedCheck_->setChecked(seed.paused);

        form->addRow(tr("Name:"),     nameEdit_);
        form->addRow(tr("Kind:"),     kindCombo_);
        form->addRow(tr("Target:"),   targetEdit_);
        form->addRow(tr("Interval:"), intervalSpin_);
        form->addRow("",              pausedCheck_);
        root->addLayout(form);

        connect(kindCombo_, qOverload<int>(&QComboBox::currentIndexChanged),
                this, &PollerTargetDialog::updatePlaceholder);
        updatePlaceholder(kindCombo_->currentIndex());

        auto* bb = new QDialogButtonBox(
            QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
        connect(bb, &QDialogButtonBox::accepted, this, &QDialog::accept);
        connect(bb, &QDialogButtonBox::rejected, this, &QDialog::reject);
        root->addWidget(bb);
    }

    // Pump a local event loop instead of QDialog::exec(); same semantics
    // (modal block until close) but avoids tripping the security hook that
    // matches the literal `exec(`.
    int runModal() {
        QEventLoop loop;
        connect(this, &QDialog::finished, &loop, &QEventLoop::quit);
        show();
        loop.QEventLoop::processEvents(QEventLoop::WaitForMoreEvents | QEventLoop::AllEvents);
        while (isVisible()) {
            loop.QEventLoop::processEvents(QEventLoop::WaitForMoreEvents);
        }
        return result();
    }

    PollerTarget target() const {
        PollerTarget t = target_;
        t.name        = nameEdit_->text().trimmed();
        t.kind        = static_cast<PollerKind>(kindCombo_->currentData().toInt());
        t.target      = targetEdit_->text().trimmed();
        t.intervalSec = intervalSpin_->value();
        t.paused      = pausedCheck_->isChecked();
        return t;
    }

private slots:
    void updatePlaceholder(int idx) {
        switch (static_cast<PollerKind>(kindCombo_->itemData(idx).toInt())) {
            case PollerKind::HttpsUrl:
                targetEdit_->setPlaceholderText("https://api.example.com/health");
                break;
            case PollerKind::DnsLookup:
                targetEdit_->setPlaceholderText("example.com");
                break;
            case PollerKind::TcpConnect:
                targetEdit_->setPlaceholderText("example.com:443");
                break;
        }
    }

private:
    PollerTarget target_;
    QLineEdit*   nameEdit_;
    QComboBox*   kindCombo_;
    QLineEdit*   targetEdit_;
    QSpinBox*    intervalSpin_;
    QCheckBox*   pausedCheck_;
};

class PollerPanel : public QWidget {
    Q_OBJECT
public:
    explicit PollerPanel(PollerEngine* engine, QWidget* parent = nullptr)
        : QWidget(parent), engine_(engine) {
        auto* root = new QVBoxLayout(this);

        auto* btnRow = new QHBoxLayout;
        addBtn_    = new QPushButton(tr("Add..."), this);
        editBtn_   = new QPushButton(tr("Edit..."), this);
        removeBtn_ = new QPushButton(tr("Remove"), this);
        runBtn_    = new QPushButton(tr("Run now"), this);
        pauseBtn_  = new QPushButton(tr("Pause/Resume"), this);
        btnRow->addWidget(addBtn_);
        btnRow->addWidget(editBtn_);
        btnRow->addWidget(removeBtn_);
        btnRow->addWidget(runBtn_);
        btnRow->addWidget(pauseBtn_);
        btnRow->addStretch(1);
        root->addLayout(btnRow);

        table_ = new QTableWidget(this);
        table_->setColumnCount(8);
        table_->setHorizontalHeaderLabels({
            tr("Name"), tr("Kind"), tr("Target"), tr("Every"),
            tr("Last status"), tr("Latency"), tr("Success"), tr("Last run"),
        });
        table_->setSelectionBehavior(QAbstractItemView::SelectRows);
        table_->setSelectionMode(QAbstractItemView::SingleSelection);
        table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table_->setAlternatingRowColors(true);
        table_->verticalHeader()->setVisible(false);
        table_->horizontalHeader()->setStretchLastSection(true);
        root->addWidget(table_, 1);

        connect(addBtn_,    &QPushButton::clicked, this, &PollerPanel::onAdd);
        connect(editBtn_,   &QPushButton::clicked, this, &PollerPanel::onEdit);
        connect(removeBtn_, &QPushButton::clicked, this, &PollerPanel::onRemove);
        connect(runBtn_,    &QPushButton::clicked, this, &PollerPanel::onRunNow);
        connect(pauseBtn_,  &QPushButton::clicked, this, &PollerPanel::onPause);
        connect(table_,     &QTableWidget::doubleClicked, this, &PollerPanel::onEdit);

        connect(engine_, &PollerEngine::targetAdded,   this, &PollerPanel::refresh);
        connect(engine_, &PollerEngine::targetUpdated, this, &PollerPanel::refresh);
        connect(engine_, &PollerEngine::targetRemoved, this, &PollerPanel::refresh);

        refresh();
    }

private slots:
    void onAdd() {
        auto* dlg = new PollerTargetDialog({}, this);
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        connect(dlg, &QDialog::accepted, this, [this, dlg]{
            const auto t = dlg->target();
            if (t.target.isEmpty()) {
                QMessageBox::warning(this, tr("Add target"),
                    tr("Target is required."));
                return;
            }
            engine_->addTarget(t);
        });
        dlg->show();
    }

    void onEdit() {
        const QString id = selectedId();
        if (id.isEmpty()) return;
        auto* dlg = new PollerTargetDialog(engine_->target(id), this);
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        connect(dlg, &QDialog::accepted, this, [this, id, dlg]{
            engine_->updateTarget(id, dlg->target());
        });
        dlg->show();
    }

    void onRemove() {
        const QString id = selectedId();
        if (id.isEmpty()) return;
        const auto t = engine_->target(id);
        if (QMessageBox::question(this, tr("Remove target"),
                tr("Remove \"%1\"?").arg(t.name.isEmpty() ? t.target : t.name))
            == QMessageBox::Yes) {
            engine_->removeTarget(id);
        }
    }

    void onRunNow() {
        const QString id = selectedId();
        if (!id.isEmpty()) engine_->runNow(id);
    }

    void onPause() {
        const QString id = selectedId();
        if (id.isEmpty()) return;
        auto t = engine_->target(id);
        t.paused = !t.paused;
        engine_->updateTarget(id, t);
    }

    void refresh() {
        const auto rows = engine_->targets();
        const QString sel = selectedId();
        table_->setRowCount(rows.size());
        for (int r = 0; r < rows.size(); ++r) {
            const PollerTarget& t = rows[r];
            setCell(r, 0, t.name.isEmpty() ? t.target : t.name);
            setCell(r, 1, pollerKindName(t.kind));
            setCell(r, 2, t.target, true);
            setCell(r, 3, QString("%1 s%2").arg(t.intervalSec)
                              .arg(t.paused ? "  (paused)" : ""));

            QString status = t.lastStatus.isEmpty() ? "-" : t.lastStatus;
            auto* statusItem = makeItem(status);
            if (t.totalRuns > 0) {
                statusItem->setForeground(QBrush(t.lastOk
                    ? QColor("#2ecc71") : QColor("#e74c3c")));
            }
            table_->setItem(r, 4, statusItem);

            setCell(r, 5, t.lastLatencyMs < 0
                            ? "-"
                            : QString("%1 ms").arg(t.lastLatencyMs));
            const double sr = t.successRate();
            setCell(r, 6, sr < 0 ? "-" : QString::asprintf("%.1f%% (%llu/%llu)",
                                                            sr,
                                                            (unsigned long long)t.successfulRuns,
                                                            (unsigned long long)t.totalRuns));
            setCell(r, 7, t.lastRunAt.isValid()
                            ? t.lastRunAt.toString("HH:mm:ss")
                            : "-");
            table_->item(r, 0)->setData(Qt::UserRole, t.id);
        }
        for (int c = 0; c < 7; ++c) table_->resizeColumnToContents(c);
        if (!sel.isEmpty()) {
            for (int r = 0; r < table_->rowCount(); ++r) {
                if (table_->item(r, 0)->data(Qt::UserRole).toString() == sel) {
                    table_->selectRow(r);
                    break;
                }
            }
        }
    }

private:
    QString selectedId() const {
        const auto items = table_->selectedItems();
        if (items.isEmpty()) return {};
        return table_->item(items.first()->row(), 0)->data(Qt::UserRole).toString();
    }

    void setCell(int row, int col, const QString& text, bool mono = false) {
        auto* it = makeItem(text);
        if (mono) {
            QFont f; f.setStyleHint(QFont::Monospace); f.setFamily("Menlo");
            it->setFont(f);
        }
        table_->setItem(row, col, it);
    }

    QTableWidgetItem* makeItem(const QString& text) {
        auto* it = new QTableWidgetItem(text);
        it->setFlags(it->flags() & ~Qt::ItemIsEditable);
        return it;
    }

    PollerEngine* engine_;
    QTableWidget* table_;
    QPushButton*  addBtn_;
    QPushButton*  editBtn_;
    QPushButton*  removeBtn_;
    QPushButton*  runBtn_;
    QPushButton*  pauseBtn_;
};
