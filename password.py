"""Utilitaire pour les mots de passe"""


class PasswordLengthWeakness(Exception):
    def __init__(self):
        super().__init__("Password length is less than 8 chars")

class PasswordSpecialCharsWeakness(Exception):
    def __init__(self):
        super().__init__("Password contains less than 2 special chars")

class PasswordNumberWeakness(Exception):
    def __init__(self):
        super().__init__("Password does not contain any number")

def isStrong(password):
    """Verifie la solidite d'un mot-de-passe"""
    specialchars = "&_-{}()@#[]|=+$%!:;,?./<>"
    # longueur
    if len(password) < 8: raise PasswordLengthWeakness()
    # caracteres speciaux : 2
    if sum([1 if char in specialchars else 0 for char in password]) < 2: raise PasswordSpecialCharsWeakness()
    # nombres
    if sum([1 if char.isdigit() else 0 for char in password]) < 1: raise PasswordNumberWeakness()