import sys
import globals as const
import databasemanager
import window
from PyQt5.QtWidgets import QApplication


if __name__ == "__main__":
    # INITIALISATION DES CSTES
    const.db = databasemanager.DataBaseManager("database/datas.db")
    # APP
    app = QApplication(sys.argv)
    # login
    result = window.doLogin()
    if result is None:
        sys.exit(0)
    else:
        # app principale
        win = window.MainWindow(result)
        win.showMaximized()
    # on quitte
    app.exec()
    # on ferme la db
    const.db.close()
    sys.exit()
