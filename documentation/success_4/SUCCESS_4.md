On vient d'avoir le message au lieu d'une erreur Bluetooth ou que l'appli n'a pas pu démarrer, qui dit qu'il manque
une ou des applications HondaLin/k sur le téléphone.

Dans ce même commit, j'ai retiré les autres hypothèses du script btsdp_iap_guided, mais si jamais pas capable de répliquer,
se fier au commit juste avant "AppMode 9".

Sur le Pi, on roule le profil HFP, on roule btsdp_iap_guided (hypothèse qu'on appelle Z2), et on se rend à cet écran./