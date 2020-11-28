#ifndef MAINWINDOW_H
#define MAINWINDOW_H
#include"peparser.h"
#include <QMainWindow>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    void open();
     ~MainWindow();


signals:
    void import1(Ui::MainWindow*);//定义一个信号，参数类型为ui
    void import2(Ui::MainWindow*);
    void import3(Ui::MainWindow*);
    void import4(Ui::MainWindow*);

private:
    bool loadFile(const QString &filename);//加载文件
    int opened=-1;
    char* filename;
    PEparser* pe;



private slots:

    void on_action_close_triggered();

    void on_action_open_triggered();

    void on_pushButton_init_clicked();

    void on_pushButton_dos_nt_header_clicked();

    void on_pushButton_sectioninfo_clicked();
    void on_pushButton_export_clicked();

private:
    Ui::MainWindow *ui;
};

#endif // MAINWINDOW_H
