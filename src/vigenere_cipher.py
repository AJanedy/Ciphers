"""
An algorithm for encrypting text.  The Vigenere cipher encodes each letter
of plaintext with a different Caesar cipher based on a key.

A Caesar cipher is a substitution cipher wherein each letter of plaintext
is replaced by a letter of some fixed number of positions down in the
alphabet.

The Vigenere cipher uses a plaintext key which is used to determine the
incremental shift of the Caesar cipher.

                             VIGENERE CYPHER:

    A  B  C  D  E  F  G  H  I  J  K  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z
  -----------------------------------------------------------------------------
A|  A  B  C  D  E  F  G  H  I  J  K  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z
B|  B  C  D  E  F  G  H  I  J  K  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z  A
C|  C  D  E  F  G  H  I  J  K  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z  A  B
D|  D  E  F  G  H  I  J  K  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z  A  B  C
E|  E  F  G  H  I  J  K  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z  A  B  C  D
F|  F  G  H  I  J  K  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z  A  B  C  D  E
G|  G  H  I  J  K  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z  A  B  C  D  E  F
H|  H  I  J  K  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z  A  B  C  D  E  F  G
I|  I  J  K  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z  A  B  C  D  E  F  G  H
J|  J  K  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z  A  B  C  D  E  F  G  H  I
K|  K  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z  A  B  C  D  E  F  G  H  I  J
L|  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z  A  B  C  D  E  F  G  H  I  J  K
M|  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z  A  B  C  D  E  F  G  H  I  J  K  L
N|  N  O  P  Q  R  S  T  U  V  W  X  Y  Z  A  B  C  D  E  F  G  H  I  J  K  L  M
O|  O  P  Q  R  S  T  U  V  W  X  Y  Z  A  B  C  D  E  F  G  H  I  J  K  L  M  N
P|  P  Q  R  S  T  U  V  W  X  Y  Z  A  B  C  D  E  F  G  H  I  J  K  L  M  N  O
Q|  Q  R  S  T  U  V  W  X  Y  Z  A  B  C  D  E  F  G  H  I  J  K  L  M  N  O  P
R|  R  S  T  U  V  W  X  Y  Z  A  B  C  D  E  F  G  H  I  J  K  L  M  N  O  P  Q
S|  S  T  U  V  W  X  Y  Z  A  B  C  D  E  F  G  H  I  J  K  L  M  N  O  P  Q  R
T|  T  U  V  W  X  Y  Z  A  B  C  D  E  F  G  H  I  J  K  L  M  N  O  P  Q  R  S
U|  U  V  W  X  Y  Z  A  B  C  D  E  F  G  H  I  J  K  L  M  N  O  P  Q  R  S  T
V|  V  W  X  Y  Z  A  B  C  D  E  F  G  H  I  J  K  L  M  N  O  P  Q  R  S  T  U
W|  W  X  Y  Z  A  B  C  D  E  F  G  H  I  J  K  L  M  N  O  P  Q  R  S  T  U  V
X|  X  Y  Z  A  B  C  D  E  F  G  H  I  J  K  L  M  N  O  P  Q  R  S  T  U  V  W
Y|  Y  Z  A  B  C  D  E  F  G  H  I  J  K  L  M  N  O  P  Q  R  S  T  U  V  W  X
Z|  Z  A  B  C  D  E  F  G  H  I  J  K  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y

The cipher works as such:
    * Sender chooses a message to encrypt: "THISISASECRET"
    * The sender also chooses a keyword: "DONTTELL"
    * The keyword repeats until it matches the length of the message:
        * Length of "THISISASECRET" = 13
        * Keyword =  DONTTELLDONTT
    * Each letter in the message corresponds to each row in the cipher and each
      letter in the key corresponds to each column:
        * Message: THISISASECRET
        * Key:     DONTTELLDONTT
            * Match row T with column D for first encryption: W
            * Match row H with column O for next encryption: V
            * The encryption follows as such [row][column]:
                * [T][D], [H][O], [I][N], [S][T], [I][T], [S][E], [A][L], [S][L],
                  [E][D], [C][O], [R][N], [E][T], [T][T]
                * Encrypted message: WVVLBWLDHQEXM

To decrypt the message:
    * Each letter in the key corresponds to each row in the cipher, then find the
      position of the corresponding letter in the encrypted message, and match it
      to the column's label:
        * Keyword:           DONTTELLDONTT
        * Encrypted message: WVVLBWLDHQEXM
            * Find the position of W in row D and match with corresponding column
              label for decryption of letter W: T
            * Find the position of V in row O and match with corresponding column
              label for decryption of letter V: H
            * The decryption follows as such [row][column]:
                *[D][] = W, [O][] = V, [N][] = V, [T][] = L, [T][] = B, [E][] = W,
                 [L][] = L, [L][] = D, [D][] = H, [O][] = Q, [N][] = E, [T][] = X,
                [T][] = M
                * Decrypted message = THISISASECRET
"""


ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def vigeneres_cipher():
    print("\nRunning Vigenere's cipher")
    selection = input("\nWould you like to encrypt (type 'e' or 'E') or decrypt (type 'd' or 'D') a message?"
                      "\nType 'q' or 'Q' to exit: ").upper()
    if selection == "E":
        encrypt_message()
    if selection == "D":
        decrypt_message()
    if selection == "Q":
        print("Exiting the program")
    else:
        print("Invalid input...")
        vigeneres_cipher()


def encrypt_message():
    plaintext = get_plaintext()
    key = get_key()
    plaintext_length = len(plaintext)
    repeating_key = get_repeating_key(key, plaintext_length)
    ciphertext = encrypt_with_vigenere(plaintext, repeating_key)
    print(f"Encrypted message: {ciphertext}")
    vigeneres_cipher()


def get_plaintext():
    plaintext = input("What is the message you would like to encrypt?: ").upper()
    if not plaintext.isalpha():
        print("Message must only include letters.  No punctuation, whitespace, or digits...")
        encrypt_message()
    else:
        return plaintext


def get_key():
    key = input("What is the key to encrypt/decrypt the message?: ")
    if not key.isalpha():
        print("Key must only include letters.  No punctuation, whitespace, or digits...")
        get_key()
    else:
        return key


def get_repeating_key(key: str, target_length: int):
    # target_lenth // len(key) calculates how many full copies of the key
    # are need to reach the target length.  We add 1 to ensure that the
    # repeated string is as long (or even exceeds) the target length.
    # Thus key * ((target_length // len(key)) + 1) repeats the string enough
    # times to be at least as long as target_length.
    # [:target_length] then slices the string down to exactly the target_length
    return ((key * ((target_length // len(key)) + 1))[:target_length]).upper()


def encrypt_with_vigenere(plaintext, repeating_key):
    encrypted_message = ""
    # Enumerate through plaintext message
    for index, letter in enumerate(plaintext):
        # Get each letter's index in the alphabet
        plaintext_index = ALPHABET.index(letter)
        # Get the index of the corresponding character in the key string
        key_index = ALPHABET.index(repeating_key[index])
        # Modulo operation on the sum of plaintext_index + key_index % 26
        # returns the index of the encrypted letter based on the Vigenere cipher
        encrypted_index = (plaintext_index + key_index) % 26
        # Concatenate the next encrypted letter to encrypted_message
        encrypted_message += ALPHABET[encrypted_index]
    return encrypted_message


def decrypt_message():
    ciphertext = get_encrypted_message()
    key = get_key()
    encrypted_message_length = len(ciphertext)
    repeating_key = get_repeating_key(key, encrypted_message_length)
    plaintext = decrypt_with_vigenere(ciphertext, repeating_key)
    print(f"Decrypted message: {plaintext}")
    vigeneres_cipher()


def get_encrypted_message():
    encrypted_message = input("What is the message you would like to decrypt?: ").upper()
    if not encrypted_message.isalpha():
        print("Message must only include letters.  No punctuation, whitespace, or digits...")
        decrypt_message()
    else:
        return encrypted_message


def decrypt_with_vigenere(ciphertext, repeating_key):
    decrypted_message = ""
    # Enumerate through plaintext message
    for index, letter in enumerate(ciphertext):
        # Get each letter's index in the alphabet
        ciphertext_index = ALPHABET.index(letter)
        # Get the index of the corresponding character in the key string
        key_index = ALPHABET.index(repeating_key[index])
        # Modulo operation on the difference of ciphertext_index - key_index % 26
        # returns the index of the original letter before encryption
        decrypted_index = (ciphertext_index - key_index) % 26
        # Concatenate the next decrypted letter to the decrypted_message
        decrypted_message += ALPHABET[decrypted_index]
    return decrypted_message


vigeneres_cipher()

