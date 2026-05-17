# Lab 17 – Cracking OWASP UnCrackable Android Level 3

**Cours :** Mobile Application Security  
**Outils utilisés :** Jadx-GUI · apktool · Ghidra · Android Studio · Python

---

## 1. Analyse statique (Jadx-GUI)

L'APK a été ouvert dans Jadx-GUI pour examiner le code Java.  
Dans `MainActivity`, la méthode `onCreate()` appelle `showDialog()` si un root ou une falsification est détectée, ce qui ferme l'application.  
La vérification du mot de passe est effectuée par `check.check_code()`, une méthode **native** — son implémentation réelle se trouve dans la bibliothèque `libfoo.so`, pas dans le code Java.
<img width="1745" height="398" alt="image" src="https://github.com/user-attachments/assets/8c910066-f3ce-466b-8f1c-6935a2426610" />
<img width="1766" height="1093" alt="image" src="https://github.com/user-attachments/assets/a77481d7-ed72-4679-82a0-67e3edfebcff" />


<img width="1790" height="347" alt="image" src="https://github.com/user-attachments/assets/c799a787-a87e-4435-9e0a-71a1b23cc68d" />
<img width="1772" height="832" alt="image" src="https://github.com/user-attachments/assets/46291fa9-4c23-415b-b97e-905a791bfa16" />
<img width="1408" height="1248" alt="image" src="https://github.com/user-attachments/assets/0f2114ee-dd2c-49f0-96e1-546e4aa5eb49" />

---

## 2. Décompilation avec apktool

```bash
java -jar apktool.jar d UnCrackable-Level3.apk -o uncrackable3
```

L'APK a été décompilé pour obtenir le code smali modifiable ainsi que les bibliothèques natives.

---
<img width="1443" height="497" alt="image" src="https://github.com/user-attachments/assets/f3d7a42f-290c-4d52-a351-a56c8fdfbbda" />
<img width="1497" height="320" alt="image" src="https://github.com/user-attachments/assets/9493e660-a21b-4c63-a4cf-b6b488390f16" />
<img width="1426" height="462" alt="image" src="https://github.com/user-attachments/assets/8ec3200d-9190-45b0-b26e-a59debca401f" />

## 3. Patch smali – Suppression de la détection root

Dans `MainActivity.smali`, le bloc appelant `showDialog("Rooting or tampering detected.")` a été remplacé par `return-void` afin de désactiver la vérification root au niveau Java.

**Avant :**
```smali
const-string v0, "Rooting or tampering detected."
invoke-direct {p0, v0}, ...->showDialog(...)V
```

**Après :**
```smali
return-void
```
<img width="1413" height="562" alt="image" src="https://github.com/user-attachments/assets/befa86f3-0c66-4bff-aded-9b3f9aaa0ac0" />
<img width="1494" height="978" alt="image" src="https://github.com/user-attachments/assets/e9a27ade-e28e-4b58-930f-db304c0a9c5f" />
<img width="1341" height="353" alt="image" src="https://github.com/user-attachments/assets/aaa0e8eb-1ec0-4042-b8f6-940684560674" />

---

## 4. Patch natif – Suppression de l'anti-debug (Ghidra)

La bibliothèque `libfoo.so` (x86_64) a été analysée dans Ghidra.  
La fonction `FUN_001037c0` (appelée automatiquement au chargement via `.init_array`) scanne `/proc/self/maps` à la recherche des chaînes `frida` et `xposed`. Si détectées, elle appelle `goodbye()` qui termine l'application.

**Patch appliqué :** la première instruction (`PUSH RBP` à l'adresse `001037c0`) a été remplacée par `RET`, forçant la fonction à retourner immédiatement sans effectuer aucune vérification.

La bibliothèque patchée a ensuite remplacé l'originale avant la recompilation.


<img width="1445" height="670" alt="image" src="https://github.com/user-attachments/assets/4895c244-daec-4d18-b6fb-ccb6a6e9a1c9" />
<img width="1499" height="1292" alt="image" src="https://github.com/user-attachments/assets/fe40d2e6-3aca-4c39-8d4f-575ce6837bf1" />
<img width="1635" height="938" alt="image" src="https://github.com/user-attachments/assets/d852070e-a939-4578-9c16-77fa327606e7" />


---

## 5. Reconstruction et installation

```bash
# Recompilation
java -jar apktool.jar b uncrackable3 -o UnCrackable-patched.apk

# Signature
apksigner sign --ks debug.keystore UnCrackable-patched.apk

# Installation
adb uninstall owasp.mstg.uncrackable3
adb install UnCrackable-patched.apk
```

<img width="1440" height="1013" alt="image" src="https://github.com/user-attachments/assets/1fa67ce5-ed69-4e98-b1cf-0184ebdd3a42" />

---

## 6. Décodage du mot de passe

### Rôle de `check_code()`

`check.check_code()` est une méthode **native** car elle implémente la logique de vérification du mot de passe en C/C++ compilé, ce qui la rend plus difficile à analyser qu'un simple code Java. Elle compare l'entrée utilisateur (24 caractères) avec une clé encodée par XOR stockée dans `libfoo.so`.

### Rôle de `FUN_001012c0` (fonction de vérification)

Cette fonction contient la logique principale de comparaison. Elle est volontairement **obfusquée** : on y trouve des centaines d'appels `malloc()`, des calculs LCG (`0x41c64e6d + 0x3039`) et des structures de listes chaînées factices — tout cela pour noyer l'analyste dans du code inutile. Les données réelles (les 24 octets encodés) sont écrites à la **fin** de la fonction dans le buffer `param_1`.

### Signes d'obfuscation observés

- Répétition de blocs `malloc(0x10)` construisant de fausses listes chaînées
- Calculs LCG (Linear Congruential Generator) sans effet utile
- Structure gonflée artificiellement (90+ itérations identiques)

### Pourquoi le buffer final est la clé

C'est dans `param_1` (le buffer de sortie) que les 24 octets encodés sont finalement écrits. En ignorant tout le bruit et en lisant uniquement ces dernières écritures, on récupère la clé encodée.

### Script de décodage

```python
# decode.py
encoded = bytes.fromhex("1d0811130f1749150d0003195a1d1315080e5a0017081314")
xor_key = b"pizzapizzapizzapizzapizzapizza"
secret = bytes(a ^ b for a, b in zip(encoded, xor_key))
print("Secret key found:", secret.decode())
```

**Résultat :**
```
Secret key found: making owasp great again
```

<img width="1434" height="161" alt="image" src="https://github.com/user-attachments/assets/775d2d81-f47a-4842-a013-749e920b15c9" />

---

## Conclusion

En combinant le patch smali (couche Java) et le patch natif Ghidra (couche C), toutes les protections ont été contournées. Le mot de passe `making owasp great again` a été extrait par analyse du flux de données XOR dans `libfoo.so`.
