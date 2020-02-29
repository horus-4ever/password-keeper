"""Les differentes fenetres et parties de l'application"""

from PyQt5.QtWidgets import QScrollArea, QDialog, QMessageBox, QMainWindow, QFileDialog, QTextEdit, QWidget, QShortcut, QSizePolicy, QTabBar, QLabel, QPushButton, QComboBox, QApplication, QHBoxLayout, QVBoxLayout, QStackedLayout, QLineEdit, QFrame, QTabWidget
from PyQt5.QtGui import QIcon, QPixmap, QColor, QPalette, QPainter, QPaintEvent, QKeyEvent, QFont, QKeySequence
from PyQt5.QtCore import *

import os
import sys
import hashlib
import password as pwd
import globals as const


# ==========================
#   LOGIN SCREEN
# ==========================
class _LoginFrame(QFrame):

    def __init__(self, parent):
        """Page de login (pas de signup)"""
        super().__init__(parent)
        self.initUI()

    def initUI(self):
        """Initialise l'UI"""
        self.mainLayout = QVBoxLayout(self)
        # widgets
        label = QLabel("<h3>Log In</h3>", self)
        self.userentry = QLineEdit(self)
        self.userentry.setPlaceholderText("username")
        self.passentry = QLineEdit(self)
        self.passentry.setPlaceholderText("password")
        self.passentry.setEchoMode(QLineEdit.Password)
        self.button = QPushButton("log in", self)
        self.button.clicked.connect(self.login)
        self.signupbutton = QPushButton("New ? Sign Up", self)
        self.signupbutton.clicked.connect(self.signup)
        #
        self.mainLayout.addWidget(label)
        self.mainLayout.addWidget(self.userentry)
        self.mainLayout.addWidget(self.passentry)
        self.mainLayout.addWidget(self.button)
        self.mainLayout.addStretch(0)
        self.mainLayout.addWidget(self.signupbutton)
        #
        self.setLayout(self.mainLayout)

    def validate(self):
        """Valide les donnees"""
        username = self.userentry.text()
        password = self.passentry.text()
        # sha512
        encryptedusername = hashlib.sha512(username.encode("utf-8")).hexdigest()
        encryptedpassword = hashlib.sha512(password.encode("utf-8")).hexdigest()
        # verification
        dbpass = const.db.getUserPassword(encryptedusername)[0][0]
        if dbpass != encryptedpassword: raise Exception()
        #
        return (username, password)

    @pyqtSlot()
    def login(self):
        """Login"""
        try:
            datas = self.validate()
        except:
            QMessageBox.critical(self, "Error", "Invalid username or password")
        else:
            self.parent().login(datas)

    @pyqtSlot()
    def signup(self):
        """Sign Up"""
        self.parent().showSignup()


class _SignupFrame(QFrame):

    def __init__(self, parent):
        """Signup frame"""
        super().__init__(parent)
        self.initUI()

    def initUI(self):
        """Init l'UI"""
        self.mainLayout = QVBoxLayout()
        # widgets
        label = QLabel("<h3>Sign Up</h3>", self)
        self.userentry = QLineEdit(self)
        self.userentry.setPlaceholderText("username")
        self.passentry = QLineEdit(self)
        self.passentry.setPlaceholderText("password")
        self.passentry.setEchoMode(QLineEdit.Password)
        self.passentry2 = QLineEdit(self)
        self.passentry2.setPlaceholderText("confirm password")
        self.passentry2.setEchoMode(QLineEdit.Password)

        self.subLayout = QHBoxLayout()
        self.signupbutton = QPushButton("register", self)
        self.signupbutton.clicked.connect(self.signup)
        self.cancelbutton = QPushButton("cancel", self)
        self.cancelbutton.clicked.connect(self.cancel)
        self.subLayout.addWidget(self.signupbutton)
        self.subLayout.addWidget(self.cancelbutton)

        #
        self.mainLayout.addWidget(label)
        self.mainLayout.addWidget(self.userentry)
        self.mainLayout.addWidget(self.passentry)
        self.mainLayout.addWidget(self.passentry2)
        self.mainLayout.addLayout(self.subLayout)
        self.setLayout(self.mainLayout)

    def validate(self):
        """Valide les donnees. Genere une exception si les donnees sont invalides"""
        # les 3 donnees
        username = self.userentry.text()
        pass1 = self.passentry.text()
        pass2 = self.passentry2.text()
        # et leur validation
        # le username
        generated = hashlib.sha512(username.encode("utf-8")).hexdigest()
        if const.db.hasUser(generated): raise Exception("This username is already taken!")
        # le mdp
        if pass1 != pass2: raise Exception("Mot-de-passe differents!")
        pwd.isStrong(pass1)
        # on essaye de retourner les donnees
        return (username, pass1)

    @pyqtSlot()
    def signup(self):
        """Valide les donnees et tente de signup"""
        try:
            datas = self.validate()
        except Exception as e:
            QMessageBox.critical(self, "Erreur", str(e))
        else:
            self.parent().signup(datas)


    @pyqtSlot()
    def cancel(self):
        """Efface le contenu de toutes les entrees et retourne a l'accueil"""
        self.parent().showLogin()


class LoginScreen(QDialog):

    def __init__(self):
        """Se connecte a l'application"""
        self._result = None
        super().__init__()
        self.initUI()

    def initUI(self):
        """Initailise le tout!"""
        # layout principal : 'login' et 'sign up'
        self.mainLayout = QStackedLayout(self)
        #
        self.loginframe = _LoginFrame(self)
        self.signupframe = _SignupFrame(self)
        # set
        self.mainLayout.addWidget(self.loginframe)
        self.mainLayout.addWidget(self.signupframe)
        self.setLayout(self.mainLayout)
        #
        self.showLogin()

    def showLogin(self):
        """Show le login frame"""
        self.mainLayout.setCurrentWidget(self.loginframe)

    def showSignup(self):
        """Show le signup frame"""
        self.mainLayout.setCurrentWidget(self.signupframe)

    def signup(self, datas):
        """Nouvelle connexion"""
        username, password = datas
        encryptedpass = hashlib.sha512(password.encode("utf-8")).hexdigest()
        encryptedusername = hashlib.sha512(username.encode("utf-8")).hexdigest()
        # ajout a la base de donnees
        const.db.addUser(encryptedusername, encryptedpass)
        # et messagebox sympathique
        QMessageBox.information(self, "Register", "You have been registered!")
        self.showLogin()

    def login(self, datas):
        """S'identifie"""
        self.close()
        self._result = datas

    def result(self):
        """Retourne le resultat"""
        return self._result

def doLogin():
    """Fait le login"""
    window = LoginScreen()
    window.exec()
    return window.result()


# =======================
#   NEW RECORD
# =======================
class _NewRecord(QDialog):

    def __init__(self, parent):
        """Popup pour une nouvelle entree"""
        self._result = None
        super().__init__(parent)
        self.initUI()

    def initUI(self):
        """Initialise l'UI"""
        self.mainLayout = QVBoxLayout()
        #
        label = QLabel("<h3>New Record</h3>", self)
        self.descriptionentry = QLineEdit(self)
        self.descriptionentry.setPlaceholderText("description")
        self.passwordentry = QLineEdit(self)
        self.passwordentry.setPlaceholderText("password")
        self.passwordentry.setEchoMode(QLineEdit.Password)

        self.sublayout = QHBoxLayout()
        self.addbutton = QPushButton("add")
        self.addbutton.clicked.connect(self.add)
        self.cancelbutton = QPushButton("cancel")
        self.cancelbutton.clicked.connect(self.cancel)
        self.sublayout.addWidget(self.addbutton)
        self.sublayout.addWidget(self.cancelbutton)
        #
        self.mainLayout.addWidget(label)
        self.mainLayout.addWidget(self.descriptionentry)
        self.mainLayout.addWidget(self.passwordentry)
        self.mainLayout.addLayout(self.sublayout)
        self.setLayout(self.mainLayout)

    def validate(self):
        """On valide les donnees"""
        name = self.descriptionentry.text()
        password = self.passwordentry.text()
        #
        if name == "" or password == "":
            raise Exception()
        #
        return (name, password)

    @pyqtSlot()
    def add(self):
        """On valide les donnees"""
        try:
            datas = self.validate()
        except:
            QMessageBox.critical(self, "Error", "All field must be filled")
        else:
            self._result = datas
            self.close()

    @pyqtSlot()
    def cancel(self):
        """Cacel button"""
        self.close()

    def result(self):
        """Retourne le resultat"""
        return self._result

def performNewRecord(parent):
    """Do a new record"""
    window = _NewRecord(parent)
    window.exec()
    return window.result()

# =======================
#   MODIFY DATAS
# =======================
class _EditDatas(QDialog):

    def __init__(self, parent, *datas):
        """Popup pour une nouvelle entree"""
        self._result = None
        self.__datas = datas
        super().__init__(parent)
        self.initUI()

    def initUI(self):
        """Initialise l'UI"""
        self.mainLayout = QVBoxLayout()
        #
        label = QLabel("<h3>Edit Datas</h3>", self)
        self.descriptionentry = QLineEdit(self.__datas[0], self)
        self.descriptionentry.setPlaceholderText("description")
        self.passwordentry = QLineEdit(self.__datas[1], self)
        self.passwordentry.setPlaceholderText("password")
        self.passwordentry.setEchoMode(QLineEdit.Password)

        self.sublayout = QHBoxLayout()
        self.addbutton = QPushButton("edit")
        self.addbutton.clicked.connect(self.edit)
        self.cancelbutton = QPushButton("cancel")
        self.cancelbutton.clicked.connect(self.cancel)
        self.sublayout.addWidget(self.addbutton)
        self.sublayout.addWidget(self.cancelbutton)
        #
        self.mainLayout.addWidget(label)
        self.mainLayout.addWidget(self.descriptionentry)
        self.mainLayout.addWidget(self.passwordentry)
        self.mainLayout.addLayout(self.sublayout)
        self.setLayout(self.mainLayout)

    def validate(self):
        """On valide les donnees"""
        name = self.descriptionentry.text()
        password = self.passwordentry.text()
        #
        if name == "" or password == "":
            raise Exception()
        #
        return (name, password)

    @pyqtSlot()
    def edit(self):
        """"""
        try:
            datas = self.validate()
        except:
            QMessageBox.critical(self, "Error", "All field must be filled")
        else:
            self._result = datas
            self.close()

    @pyqtSlot()
    def cancel(self):
        """Cacel button"""
        self.close()

    def result(self):
        """Retourne le resultat"""
        return self._result

def editDatas(parent, *datas):
    """Edit les donnes"""
    window = _EditDatas(parent, *datas)
    window.exec()
    return window.result()


# =======================
#   MAIN APPLICATION
# =======================
class _MenuBar(QFrame):

    def __init__(self, parent):
        """Menu de l'application"""
        self._parent = parent
        super().__init__(parent)
        self.initUI()

    def initUI(self):
        """Initialise l'UI"""
        self.mainLayout = QHBoxLayout(self)
        # widgets*
        self.disconnectbutton = QPushButton(QIcon(QPixmap("assets/logout.png")), "", self)
        self.disconnectbutton.setIconSize(QSize(32, 32))
        self.disconnectbutton.clicked.connect(self.logout)
        self.addbutton = QPushButton(QIcon(QPixmap("assets/plus.png")), "", self)
        self.addbutton.setIconSize(QSize(32, 32))
        self.addbutton.clicked.connect(self.add)
        #
        self.mainLayout.addWidget(self.disconnectbutton)
        self.mainLayout.addWidget(self.addbutton)
        self.mainLayout.addStretch(0)
        self.setLayout(self.mainLayout)

    def logout(self):
        """Logout"""
        self._parent.logout()

    def add(self):
        """Prompt the user for a new record"""
        result = performNewRecord(self)
        if result is None:
            return
        else:
            self._parent.add(*result)

class _MainWidget(QFrame):
    FRAME_STYLESHEET = """
    .QFrame {
        background-color: #bff;
    }
    """
    def __init__(self, parent):
        """New custom scroll area"""
        self._parent = parent
        self.__datas = {}
        #
        super().__init__()
        self.initUI()

    def initUI(self):
        """Initialise l'UI"""
        self.mainLayout = QVBoxLayout(self)
        self.setLayout(self.mainLayout)
        self.mainLayout.addStretch(0)
        self.mainLayout.setDirection(QVBoxLayout.BottomToTop)

    @pyqtSlot(str)
    def search(self, value):
        """Search bar"""
        if value == "":
            for obj in self.__datas.values():
                obj.setHidden(False)
            return
        # si value n'est pas nul...
        for name, obj in self.__datas.items():
            if value in name.lower():
                obj.setHidden(False)
            else:
                obj.setHidden(True)

    def addWidget(self, name, password):
        """Cree un nouveau widget"""
        frame = QFrame()
        frame.__datas = (name, password)
        frame.setFocus()
        frame.setFrameStyle(QFrame.StyledPanel)
        frame.setLineWidth(5)
        self.setStyleSheet(self.FRAME_STYLESHEET)
        layout = QHBoxLayout(frame)
        #layout.setContentsMargins(0, 0, 0, 0)
        #
        what = QLabel(f"<strong>{name}</strong>", frame)
        what.setToolTip(password)
        button = QPushButton(QIcon(QPixmap("assets/remove.png")), "", frame)
        button.setIconSize(QSize(20, 20))
        button.clicked.connect((lambda _: self.remove(frame)))
        modifybutton = QPushButton(QIcon(QPixmap("assets/modify.png")), "", self)
        modifybutton.setIconSize(QSize(20, 20))
        modifybutton.clicked.connect(lambda _: self.modify(frame))
        #
        layout.addWidget(what)
        layout.addStretch(0)
        layout.addWidget(button)
        layout.addWidget(modifybutton)
        #
        frame.setLayout(layout)
        self.mainLayout.addWidget(frame)
        #
        self.__datas[name] = frame

    def remove(self, widget):
        """"""
        result = QMessageBox.question(self, "Suppress", "Do you really want to erase this entry?", QMessageBox.Yes | QMessageBox.No)
        if result == QMessageBox.No:
            return
        # sinon, si l'utilisateur accepte
        name, password = widget.__datas
        widget.setParent(None)
        self.mainLayout.removeWidget(widget)
        #
        w = self.__datas[name]
        w.destroy()
        del self.__datas[name]
        # vers le haut
        self._parent.remove(name, password)

    def modify(self, widget: QFrame):
        """Modifie l'entree"""
        name, password = widget.__datas
        #
        result = editDatas(self, name, password)
        if result is None:
            return
        # sinon
        widget.__datas = result
        # on modifie les widgets
        label: QLabel = widget.findChild(QLabel)
        label.setText(f"<strong>{result[0]}</strong>")
        label.setToolTip(result[1])
        #
        w = self.__datas[name]
        w.destroy()
        self.__datas.pop(name)
        self.__datas[result[0]] = widget
        # on modifie la base de donnees
        self._parent.modify(name, password, *result)


class MainWindow(QMainWindow):

    def __init__(self, infos):
        """Fenetre Principale"""
        self.__infos = infos
        #
        super().__init__()
        self.initUI()

    def initUI(self):
        """Initialise l'UI"""
        self.setWindowTitle("PasswordKeeper")
        #
        self.centralwidget = QFrame(self)
        self.mainLayout = QVBoxLayout(self.centralwidget)
        self.centralwidget.setLayout(self.mainLayout)
        # SCROLLAREA
        self.scrollarea = QScrollArea(self)
        self.scrollarea.setWidgetResizable(True)
        self.passwordframe = _MainWidget(self)
        self.scrollarea.setWidget(self.passwordframe)
        self.scrollarea.setSizePolicy(QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding))
        # MENU
        self.menubar = _MenuBar(self)
        # SEARCH BAR
        self.searchbar = QLineEdit(self)
        self.searchbar.setPlaceholderText("enter query")
        self.searchbar.textChanged.connect(self.passwordframe.search)
        #
        self.mainLayout.addWidget(self.menubar)
        self.mainLayout.addWidget(self.searchbar)
        self.mainLayout.addWidget(self.scrollarea)
        #
        self.setCentralWidget(self.centralwidget)
        # puis toutes les entrees de la db
        self.initFromDB()

    def initFromDB(self):
        """Initialise depuis le base de donnees"""
        username = hashlib.sha512(self.__infos[0].encode("utf-8")).hexdigest()
        key = hashlib.sha512(self.__infos[0].encode("utf-8")).hexdigest() + self.__infos[1]
        key = hashlib.sha256(key.encode("utf-8")).digest()
        # boucle
        for name, password in const.db.getUserDatas(username):
            name = const.AES.decrypt(key, bytes.fromhex(name)).decode("utf-8")
            # dechiffrement mot-de-passe
            password = const.AES.decrypt(key, bytes.fromhex(password)).decode("utf-8")
            self.passwordframe.addWidget(name, password)

    def add(self, name, password):
        """Ajoute une entree"""
        # creation de la cle
        key = hashlib.sha512(self.__infos[0].encode("utf-8")).hexdigest() + self.__infos[1]
        key = hashlib.sha256(key.encode("utf-8")).digest()
        # encryption
        encryptedname = const.AES.encrypt(key, name).hex()
        encryptedpassword = const.AES.encrypt(key, password).hex()
        # le nom d'utilisateur
        username = hashlib.sha512(self.__infos[0].encode("utf-8")).hexdigest()
        # on l'enleve de la base de donnees
        const.db.addUserData(username, encryptedname, encryptedpassword)
        # si tout se passe bien
        self.passwordframe.addWidget(name, password)

    def remove(self, name, password):
        """Detruit l'entree correspondante"""
        # creation de la cle
        key = hashlib.sha512(self.__infos[0].encode("utf-8")).hexdigest() + self.__infos[1]
        key = hashlib.sha256(key.encode("utf-8")).digest()
        # encryption
        encryptedname = const.AES.encrypt(key, name).hex()
        encryptedpassword = const.AES.encrypt(key, password).hex()
        # le nom d'utilisateur
        username = hashlib.sha512(self.__infos[0].encode("utf-8")).hexdigest()
        # on l'enleve de la base de donnees
        const.db.deleteUserData(username, encryptedname, encryptedpassword)

    def modify(self, name, password, newname, newpassword):
        """Update la base de donnees"""
        # creation de la cle
        key = hashlib.sha512(self.__infos[0].encode("utf-8")).hexdigest() + self.__infos[1]
        key = hashlib.sha256(key.encode("utf-8")).digest()
        # encryption
        encryptedname = const.AES.encrypt(key, name).hex()
        encryptedpassword = const.AES.encrypt(key, password).hex()
        encryptednewname = const.AES.encrypt(key, newname).hex()
        encryptednewpassword = const.AES.encrypt(key, newpassword).hex()
        # le nom d'utilisateur
        username = hashlib.sha512(self.__infos[0].encode("utf-8")).hexdigest()
        # base de donnee
        const.db.editUserData(username, encryptedname, encryptedpassword, encryptednewname, encryptednewpassword)

    def logout(self):
        """Logout"""
        self.close()
        self.destroy()