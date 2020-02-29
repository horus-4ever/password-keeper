import sqlite3
import os


class UniqueConstraintError(Exception):
    def __init__(self):
        super().__init__("User already exists!")

class UserNotFoundError(Exception):
    def __init__(self):
        super().__init__("Not such a user!")


class DataBaseManager:

    # le SQL
    GET_USERS = "SELECT username FROM users;"
    ADD_USER = "INSERT INTO users (username, password) VALUES ('{0}', '{1}');"
    DELETE_USER = "DELETE FROM users WHERE username = '{0}';"
    DELETE_USER_TABLE = "DROP TABLE '{0}';"
    UPDATE_USER_INFOS = "ALTER TABLE '{0}' RENAME TO '{1}'; UPDATE users SET username = '{1}' WHERE username = '{0}';"

    CREATE_USER_TABLE = "CREATE TABLE '{0}' ('name' TEXT, 'password' TEXT);"
    GET_USER_DATAS = "SELECT * FROM '{0}';"
    GET_USER_PASSWORD = "SELECT password FROM users WHERE username = '{0}';"
    ADD_USER_DATA = "INSERT INTO '{0}' VALUES('{1}', '{2}');"
    UPDATE_USER_DATA = "UPDATE '{0}' SET name = '{3}', password = '{4}' WHERE name = '{1}' AND password = '{2}';"
    DELETE_USER_DATA = "DELETE FROM '{0}' WHERE name = '{1}' AND password = '{2}';"

    def __init__(self, database):
        """Nouveau gestionnaire de base de donnee"""
        if not os.path.exists(database):
            raise FileNotFoundError()
        # si la base existe, on s'y connecte
        self._connexion = sqlite3.connect(database)

    def getUsers(self):
        """Retourne tous les utilisateurs"""
        action = self._connexion.execute(self.GET_USERS)
        return list(action)

    def getUserPassword(self, name):
        """Retourne le mot de passe associe a un utilisateur"""
        if not self.hasUser(name):
            raise UserNotFoundError()
        return list(self._connexion.execute(self.GET_USER_PASSWORD.format(name)))

    def getUserDatas(self, name):
        """Retourne les donnees de l'utilisateur"""
        if not self.hasUser(name):
            raise UserNotFoundError()
        # sinon, on retourne les donnees
        return list(self._connexion.execute(self.GET_USER_DATAS.format(name)))

    def hasUser(self, name):
        """Retourne si l'utilisateur est present ou non"""
        for user, *_ in self.getUsers():
            if user == name:
                return True
        else:
            return False


    def addUser(self, name, password):
        """Ajoute un utilisateur"""
        try:
            self._connexion.execute(self.ADD_USER.format(name, password))
            self._connexion.execute(self.CREATE_USER_TABLE.format(name))
        except Exception as e:
            print(e)
            raise UniqueConstraintError()
        else:
            self._connexion.commit()

    def deleteUser(self, name):
        """Supprimme un utilisateur"""
        self._connexion.execute(self.DELETE_USER.format(name))
        self._connexion.execute(self.DELETE_USER_TABLE.format(name))
        self._connexion.commit()

    def addUserData(self, user, name, password):
        """Ajoute des donnees utilisateur"""
        self._connexion.execute(self.ADD_USER_DATA.format(user, name, password))
        self._connexion.commit()

    def editUserData(self, user, name, password, newname, newpassword):
        """Actualise les donnees"""
        self._connexion.execute(self.UPDATE_USER_DATA.format(user, name, password, newname, newpassword))
        self._connexion.commit()

    def deleteUserData(self, user, name, password):
        """Retire de donnees utilisateur"""
        self._connexion.execute(self.DELETE_USER_DATA.format(user, name, password))
        self._connexion.commit()

    def close(self):
        """Close the connexion"""
        self._connexion.close()


if __name__ == "__main__":
    pass