"""
A double transposition cipher is an encryption method wherein transpostion is applied
twice to a plaintext message.

Step 1: A plaintext message is written into a grid with a fixed number of columns.
    For example the message "thisisthemessage" could be written in a 4x4 matrix
    with rows "this", "isth", "emes", "sage".
        [t h i s]
        [i s t h]
        [e m e s]
        [s a g e]
Step 2: Apply the first permutation.  For the previous 4x4 example, a column
    permutation of [3, 4, 1, 2] would have the first column become the third, the
    second column become the first, the third column would become the fourth, and the
    fourth column would become the second.
        [i s t h]
        [t h i s]
        [e s e m]
        [g e s a]
Step 3: Apply the second permutation.  A row permutation of [4, 3, 2, 1] would see
    the first row become the fourth, the second row become the third, the third row
    become the second, and the fourth row become the first.
        [g e s a]
        [e s e m]
        [t h i s]
        [i s t h]

=======================================================================================

The message below was encrypted with a double transposition using a matrix of
7 rows and 10 columns. Hint: the first word is ‘there’. Decrypt this ciphertext.

IAUTMOCSMNIMREBOTNELSTRHEREOAEVMWIH
TSEEATMAEOHWHSYCEELTTEOHMUOUFEHTRFT

Outline an automated attack on a double transposition cipher, assuming that the
size of the matrix is known.

=======================================================================================

With a 7x10 matrix there are 7! = 5,040 possible row permutations and 10! = 3,628,000
column permutations, meaning that there are a total of ~18 billion possible key
combinations, making brute force an exceptionally expensive operation.

Because of the way a double transposition cipher works, we know that every row in the
encrpyted message, as well as every column, contains the same letters as some row and
some column in the original message, they are just rearranged.  In the example provided
at the beginning of this docstring, you can see how every row in the encrypted message
has the same letters (just rearranged) as some row in the original message.  The same
can be said for the columns.

Because of this, and because we know that the word "there" is the first word in the
original message, we can create our 7x10 matrix out of the original message:

    [I A U T M O C S M N]
    [I M R E B O T N E L]
    [S T R H E R E O A E]
    [V M W I H T S E E A]
    [T M A E O H W H S Y]
    [C E E L T T E O H M]
    [U O U F E H T R F T]

===========================================================================================

            STEP 1: CREATE A 7x10 MATRIX WITH THE PROVIDED CIPHERTEXT

A method for creating this matrix from the provided ciphertext is included below.
ciphertext_to_matrix will return and print the 7x10 matrix to the terminal.

===========================================================================================

    STEP 2: FIND THE ROW THAT CONTAINS ALL THE NECESSARY LETTERS TO FIND THE KNOWN WORD

We first locate the row that contains all the letters necessary to create the word
"there".  The method find_known_word_rows() is included in this module. It returns and
prints a list of all rows containing the necessary letters.  In this case there is only
one row that contains all the necessary letters

===========================================================================================

  STEP 3: TRY TO REARRANGE THE COLUMNS IN THE KNOWN ROW SO THAT WE MATCH OUR KNOWN INFO

We are going to find all permutations of columns that result in the row containing
the necessary letters to spell "THERE" are located in the proper order from [0:5]

Since we know where "THERE" should be, we can rearrange columns until the first word is
"THERE".  In this example, the row containing the necessary letters (row 3) contains
only one "T", and one "H", so we say with certainty that those columns are the
first and second, respectively.  There are two instances of the letter "R" and 3 instances
of the letter "E".  We will find every permutation that meets these criteria.

After we find all permutations where "THERE" is the first word, there are another 5 columns
where we need to find all possible permutations.

There are 12 possible permutations where "THERE" exists in the first column without
regard to the permutations of the other 5 columns.  Since there are 5! = 120 possible
permutations of the last 5 columns, this will result in 12 x 120 = 1440 possible
permutations.

===========================================================================================

        STEP 4: MOVE "THERE" TO KNOWN LOCATION.  FIND PERMUTATIONS OF ALL OTHER ROWS

We now have 1440 matrices where row 3 (index 2) has "THERE" as the first word.  We then take
every one of those permutations, move row 3 (index 2) to the top row, to give us the 720
permutations where "THERE" is in the known location.  We will then apply permutations on
the remaining 6 rows.  Since there are 6! = 720 possible permutations of the remaining
rows, and since there are 1440 matrices to perform these permutations on, we will have a
list of 1,036,800 possible plaintext messages.

===========================================================================================

                        STEP 5: TURN EACH MATRIX BACK INTO A STRING

Here we use the numpy.flatten method to unpack each array into a string

===========================================================================================

                STEP 6: COMPARE EACH MESSAGE TO A LIST OF KNOWN WORDS

At first, a list of very common words is created, words like 'the', 'and', 'that',
'this', etc.  We then create a threshold for how many of those words need to match
each possible plaintext message for it to be saved as a possible match.  The threshold was
quickly set to 10 to minimize the number of returned possible matches.  These matches are
then viewed manually to try to discern any significant keywords.  Once it is certain
that those words are in the decrypted message, they are tested for specifically so we can
return an even smaller selection of possible matches.  That small list of possible matches
is then easily read manually to discern the decrypted message.  In this case the string
that returns the most amount of matched words is clearly the correct decrypted message.

===========================================================================================
"""
import numpy as np
from collections import Counter
from itertools import permutations
from copy import deepcopy

# Provided ciphertext
CIPHERTEXT = "IAUTMOCSMNIMREBOTNELSTRHEREOAEVMWIHTSEEATMAEOHWHSYCEELTTEOHMUOUFEHTRFT"
# Matrix size
ROWS, COLUMNS = 7, 10
# Known first word
THERE = "THERE"
t_h_updated_matrix = []
penultimate_matrices = []
matrices_with_there_at_top = []
unpacked_messages = []

common_words = ['there', 'the', 'is', 'are', 'we', 'hello', 'this', 'that', 'it', 'how', 'what', 'when', 'you',
                'to', 'be', 'have', 'with', 'from', 'they', 'not', 'as', 'on', 'of', 'and', 'in', 'for', 'do',
                'or', 'say', 'them', 'he', 'her', 'she', 'his', 'him', 'them', 'by']


def print_step_one():
    print(
        """
===================================================================================================
                    Step 1: Reconstruct the ciphertext into a matrix.
===================================================================================================
            """
    )


def ciphertext_to_matrix():
    print_step_one()
    # Convert ciphertext to matrix using numpy's .array function
    matrix = np.array(list(CIPHERTEXT)).reshape(ROWS, COLUMNS)
    print(f"The {ROWS}x{COLUMNS} matrix created from {CIPHERTEXT}: \n")
    for row in matrix:
        print(*row)
    return matrix


def print_step_two():
    print(
        """
===================================================================================================
Step 2: Find the row that contains the letters necessary to build the known word
===================================================================================================
            """
    )


def find_rows_containing_all_letters(matrix):
    print_step_two()
    word_counter = Counter(THERE)
    matching_rows = []

    for row_number, row in enumerate(cipher_matrix):
        row_string = ''.join(row)
        row_counter = Counter(row_string)

        if all(row_counter[char] >= word_counter[char] for char in word_counter):
            matching_rows.append(row_number)

    print(f"Finding rows that contain all letters needed to build the word {THERE}")
    print(f"    Matching row by index(es): "
          f"{['Row {0}: {1}'.format(row, ''.join(map(str, matrix[row]))) for row in matching_rows]}")

    return matching_rows


def print_step_three():
    print(
        """
===================================================================================================
Step 3: Find all column permutations that result in the first word "THERE"
===================================================================================================
            """
    )


def find_valid_column_permutations(matrix_row_index):
    print_step_three()
    letter_positions = find_indexes_of_matching_letters(matrix_row_index)
    transpose_one_to_one_matches(letter_positions)
    e_positions = get_remaining_indexes(letter_positions)
    valid_e_permutations = get_valid_permutations(e_positions)
    find_valid_transpositions(valid_e_permutations)


def find_indexes_of_matching_letters(matrix_row_index):
    row = cipher_matrix[matrix_row_index]
    print(f"Analyzing row with index {matrix_row_index}: {''.join(row)}\n")
    # Find the positions of the target word's letters in the row
    letter_positions = {char: [] for char in THERE}
    for i, char in enumerate(row):
        if char in THERE:
            letter_positions[char].append(i)
    print(f"Column indexes of target letters -> {letter_positions}\n")
    return letter_positions


def transpose_one_to_one_matches(letter_positions):
    print("Transposing 1 to 1 matched letters in matrix:")
    for key, value in letter_positions.items():
        if len(value) == 1:
            current_index = value[0]
            target_index = THERE.index(key)

            if current_index != target_index:
                transpose_single_count_columns(current_index, target_index)


def get_remaining_indexes(letter_positions):
    e_positions = letter_positions['E']
    print(f"\nCipher matrix column indexes for 'E': {e_positions}")

    return e_positions


def get_valid_permutations(e_positions):
    # Generate all valid permutations where 'E' is at indexes 2 & 4, and 'R' at index 3
    valid_e_permutations = list(permutations(e_positions, 2))  # E at [2,4]
    print(f"\nValid 'E' permutations: {valid_e_permutations}\n")
    return valid_e_permutations


def find_valid_transpositions(e_permutations):
    target_columns_for_e, target_columns_for_r = get_target_columns()
    transposed_matrix = []
    first_transposed_matrices = []
    list_of_matrices_with_there_as_first_word = []

    process_e_permutations(e_permutations, first_transposed_matrices, target_columns_for_e, transposed_matrix)
    process_r_permutations(first_transposed_matrices, list_of_matrices_with_there_as_first_word, target_columns_for_r)
    print_matrices_with_there_as_first_word(list_of_matrices_with_there_as_first_word)

    get_penultimate_matrices(list_of_matrices_with_there_as_first_word, penultimate_matrices)

    # print_penultimate_matrices(penultimate_matrices)


def print_penultimate_matrices(penultimate_matrices):
    print("Printing penultimate matrices:\n")
    for matrix in penultimate_matrices:
        for row in matrix:
            print(*row)
        print()
    print(f"Number of possible permutations: {len(penultimate_matrices)}")


def get_penultimate_matrices(list_of_matrices_with_there_as_first_word, penultimate_matrices):
    print("Creating list of matrices that include all permutations where 'THERE' is the first word")
    for matrix in list_of_matrices_with_there_as_first_word:
        columns = [list(col) for col in zip(*matrix)]  # Transpose rows -> columns

        # Identify columns containing "THERE"
        fixed_indices = get_fixed_indices(matrix)

        if not fixed_indices:
            print(f"Warning: No 'THERE' found in row 3 for matrix: \n{matrix}")
            continue  # Skip this matrix if 'THERE' is not found

        remaining_indices = [i for i in range(COLUMNS) if i not in fixed_indices]

        # Extract columns to be permuted
        columns_to_permute = [columns[i] for i in remaining_indices]

        # Generate permutations of these columns
        for perm in permutations(columns_to_permute):
            new_columns = deepcopy(columns)  # Deep copy for safety
            for idx, col_data in zip(remaining_indices, perm):
                new_columns[idx] = col_data  # Place permuted columns

            # Convert columns back to rows
            new_matrix = [list(row) for row in zip(*new_columns)]
            penultimate_matrices.append(deepcopy(new_matrix))

    print("Expected vs. Generated number of permutations where 'THERE' is the first word")
    print(f"Expected: {len(list_of_matrices_with_there_as_first_word) * 120}, Generated: {len(penultimate_matrices)}")
    return penultimate_matrices


def get_fixed_indices(matrix):
    row_str = ''.join(matrix[2])  # Join characters into a string
    start_idx = row_str.find("THERE")  # Find the start index of "THERE"

    if start_idx == -1:
        print(f"Warning: 'THERE' not in matrix row: \n{matrix[2]}")
        return []

    return list(range(start_idx, start_idx + 5))  # Get 5 column indices


def print_matrices_with_there_as_first_word(list_of_matrices_with_there_as_first_word):
    print("Matrix permutations where 'THERE' is the first word in row 3 (index 2)")
    print("This list does not include all 5! permutations of the final 5 letters.\n")
    for matrix in list_of_matrices_with_there_as_first_word:
        for row in matrix:
            print(*row)
        print()


def process_r_permutations(first_transposed_matrices, list_of_matrices_with_there_as_first_word, target_columns_for_r):
    target_column = target_columns_for_r[0]  # Column where 'R' needs to go

    for matrix in first_transposed_matrices:
        # Find index of 'R' in target row
        source_columns = [i for i, char in enumerate(matrix[2]) if char == 'R']
        # print(f"Index(es) of 'R' in following matrix: {source_columns}\n")
        #
        # for row in matrix:
        #     print(*row)
        # print()

        for source_column in source_columns:
            copy_matrix = matrix.copy()
            for row in copy_matrix:
                row[target_column], row[source_column] = row[source_column], row[target_column]
            list_of_matrices_with_there_as_first_word.append([row.copy() for row in copy_matrix])


def process_e_permutations(e_permutations, first_transposed_matrices, target_columns_for_e, transposed_matrix):
    for e_perm in e_permutations:
        transposed_matrix.clear()
        transposed_matrix = [list(row.replace(" ", "")) for row in t_h_updated_matrix]
        e_perm = list(e_perm)
        for source_column, target_column in zip(e_perm, target_columns_for_e):
            for row in transposed_matrix:
                row[target_column], row[source_column] = row[source_column], row[target_column]
        first_transposed_matrices.append([row.copy() for row in transposed_matrix])


def get_target_columns():
    target_columns_for_e = [i for i, char in enumerate(THERE) if char == "E"]
    target_columns_for_r = [i for i, char in enumerate(THERE) if char == 'R']
    print(f"Index(es) of 'E' in '{THERE}': {target_columns_for_e}")
    print(f"Index(es) of 'R' in '{THERE}': {target_columns_for_r}\n")
    return target_columns_for_e, target_columns_for_r


def transpose_single_count_columns(from_idx, to_idx):
    # Loop through every row in the cipher_matrix and swap the columns
    for row in cipher_matrix:
        # Swap the two columns for each row
        row[from_idx], row[to_idx] = row[to_idx], row[from_idx]

    t_h_updated_matrix.clear()

    print(f"\nMatrix after transposing columns {from_idx} and {to_idx}: \n")

    for row in cipher_matrix:
        t_h_updated_matrix.append("".join(row + " "))
        print(*row)


def print_step_four():
    print(
        """
===================================================================================================
Step 4: Move "THERE" to top row, find all permutations of remaining 6 rows
===================================================================================================
            """
    )


def move_there_to_top(matrices: list):
    print_step_four()
    for matr in matrices:
        new_matrix = matr[:]  # Create a copy to avoid modifying the original list
        row_to_move = new_matrix.pop(2)  # Remove row at index 2
        new_matrix.insert(0, row_to_move)  # Insert at the top (index 0)
        matrices_with_there_at_top.append(new_matrix)


def apply_row_permutation(matrix, row_perm):
    # Make a copy of the matrix to avoid modifying the original one
    permuted_matrix = matrix.copy()

    # Apply the row permutations on rows 2-7 (index 1-6)
    permuted_matrix[1:7] = [matrix[i] for i in row_perm]  # Apply permutation to the bottom 6 rows

    return permuted_matrix


def find_all_permutations(matrices):
    valid_matrices = []

    # Generate all permutations for rows 2-7 (index 1-6)
    row_permutations = list(permutations(range(1, 7)))  # 6! permutations for rows 2-7 (index 1-6)

    for matrix in matrices:
        # Apply each permutation to the current matrix
        for perm in row_permutations:
            permuted_matrix = apply_row_permutation(matrix, perm)

            # Check if the first word of the permuted matrix is "THERE"
            # We check the first 5 characters of the first row
            if "".join(permuted_matrix[0][:5]) == "THERE":
                valid_matrices.append(permuted_matrix)

    return valid_matrices


def print_step_five():
    print(
        """
===================================================================================================
Step 5: Unpack each matrix into a single plaintext message
===================================================================================================
            """
    )
    print("Creating a list to hold every possible plaintext message as a string...")


def unpack_matrices(matrices):
    print_step_five()
    for matrix in matrices:
        np_matrix = np.array(matrix)
        unpacked_messages.append(decrypt(np_matrix))


def decrypt(matr):
    return ''.join(matr.flatten())


def print_step_six():
    print(
        """
===================================================================================================
Step 6: Compare unpacked messages to see if they contain likely words
===================================================================================================
            """
    )


def is_likely_message(string, threshold):
    # Check if the string starts with 'THERE'
    if string[:5] != "THERE":
        return False

    # Count how many common words are in the matrix string
    found_words = 0
    for word in common_words:
        if word.upper() in string[:70]:
            found_words += 1

    # Check if the number of found words meets the threshold
    if found_words >= threshold:
        return True

    return False


def search_likely_messages(strings, threshold):
    print_step_six()
    likely_messages = []

    for string in strings:
        if is_likely_message(string, threshold):

            # Check how many common words are found in the matrix string
            found_words = [word for word in common_words if word.upper() in string]

            # If the number of words found is greater than or equal to the threshold, add it to filtered list
            if len(found_words) >= threshold:
                likely_messages.append((string, found_words))

    likely_messages.sort(key=lambda x: len(x[1]), reverse=False)

    return likely_messages


"""
===========================================================================================
PROGRAM ENTRY
===========================================================================================
"""


def run_double_transposition_decryption():
    global cipher_matrix, final_matrices, message
    print_program_prompt()

    cipher_matrix = ciphertext_to_matrix()  # Create source ciphertext matrix
    matched_rows = find_rows_containing_all_letters(cipher_matrix)  # Find rows containing the necessary letters

    # Entry point for first half of decryption.  This is designed only to work on one row_index, program
    # is not proven with multiple rows containing all key letter matches.  find_valid_column_permutations()
    # will find all 1440 permutations where 'THERE' is the first word in the third row (index 2) of the
    # original source ciphertext matrix; it completes all possible column permutations given the known
    # constraints
    for row_index in matched_rows:
        find_valid_column_permutations(row_index)

    # Move 'THERE' to it's known location at the beginning of the ciphertext matrix for
    # all 1440 possible (currently) permutations
    move_there_to_top(penultimate_matrices)

    # find_all_permutations() completes the remaining decryption by finding all transpositions of
    # rows 2-7 (indexes 1-6); this completes the remaining row permutations/transpositions
    final_matrices = find_all_permutations(matrices_with_there_at_top)
    print(f"Total number of possible plaintext messages: {len(final_matrices)}")

    # Creates a list of all the possible decrytped messages.  Matrix contents are flattened
    # into uniformly formatted strings and appended to a list of all possible messages.
    unpack_matrices(final_matrices)

    # search_likely_messages returns a list of strings from the total list of possible decoded plaintext
    # messages if they meet a minimum threshold of number of words matching a list of common words and
    # discovered words
    likely_messages = search_likely_messages(unpacked_messages, threshold=10)

    print("Filtered likely messages:")
    # As our filtered list of possible plaintext messages becomes more targeted, we can start
    # to isolate likely words found in the text.  We then use these new keywords to further
    # isolate the most likely decrypted message
    found_likely_words = ["FUTURE", "COMMUNISM", "WAVE", "BERLIN", "SOME", "WHO", "SAY"]
    most_likely_plaintext = []
    for message, matched_words in likely_messages:
        if all(word in message for word in found_likely_words):
            print(f"{message}, Matched words: {len(matched_words)}")

            if len(matched_words) == 14:
                most_likely_plaintext.append(message)

    print("\nMost likely plaintext messages:")
    for message in most_likely_plaintext:
        print(message)

    all_words = found_likely_words + common_words
    for word in all_words:
        message = most_likely_plaintext[-1].replace(word, word + " ")
    print(f"\n{message}")


def print_program_prompt():
    print("\nThe message below was encrypted with a double transposition using a matrix of \n"
          "7 rows and 10 columns. Hint: the first word is ‘there’. Decrypt this ciphertext.\n"
          "\n"
          "IAUTMOCSMNIMREBOTNELSTRHEREOAEVMWIH\n"
          "TSEEATMAEOHWHSYCEELTTEOHMUOUFEHTRFT\n"
          "\n"
          "Outline an automated attack on a double transposition cipher, assuming that the\n"
          "size of the matrix is known.")


run_double_transposition_decryption()
