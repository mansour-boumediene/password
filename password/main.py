import hashlib
caracteres_speciaux = {'!', '@', '#', '$', '%', '^', '&', '*'}
def verif(mot_de_passe):
    while True:
        if len(mot_de_passe) < 8:
            print("Veuillez saisir un mot de passe avec au moins 8 caractères.")
        elif not any(i in caracteres_speciaux for i in mot_de_passe):
            print("Le mot de passe doit contenir un caractère spécial parmi !, @, #, $, %, ^, &, *.")
        elif not any(c.isdigit() for c in mot_de_passe):
            print("Le mot de passe doit contenir au moins un chiffre.")
        elif not any(c.islower() for c in mot_de_passe):
            print("Le mot de passe doit contenir au moins une lettre minuscule.")
        elif not any(c.isupper() for c in mot_de_passe):
            print("Le mot de passe doit contenir au moins une lettre majuscule.")
        else:
            print("Mot de passe sécurisé")
            return mot_de_passe


mot_de_passe_valide = verif(input("Créez un mot de passe : "))
if mot_de_passe_valide:
    hashed_password = hashlib.sha256(mot_de_passe_valide.encode('utf-8')).hexdigest()
    print("Mot de passe haché :", hashed_password)

