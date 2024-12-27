<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cipher Algorithms</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            background-color: #f0f8ff;
        }
        form {
            width: 100%;
            max-width: 400px;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            background-color: #ffffff;
            display: flex;
            flex-direction: column;
            align-items: center;
        }
        h1 {
            text-align: center;
            margin-bottom: 20px;
            color: #333;
        }
        label {
            width: 100%;
            margin-top: 10px;
            font-weight: bold;
            color: #555;
        }
        textarea, input, select, button {
            width: 100%;
            padding: 10px;
            margin-top: 5px;
            margin-bottom: 15px;
            border: 1px solid #ccc;
            border-radius: 5px;
        }
        textarea {
            resize: vertical;
        }
        #message {
            min-height: 70px;
        }
        #key {
            min-height: 40px;
        }
        button {
            background-color: #4CAF50;
            color: white;
            border: none;
            cursor: pointer;
        }
        button:hover {
            background-color: #45a049;
        }
        .result {
            margin: 20px 0;
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 5px;
            background-color: #f9f9f9;
        }
    </style>
</head>
<body>
    <form method="POST" action="">
        <h1>Cipher Algorithms</h1>
        <label for="algorithm">Choose Algorithm:</label>
        <select name="algorithm" id="algorithm" required>
            <option value="caesar">Caesar Cipher</option>
            <option value="playfair">Playfair Cipher</option>
            <option value="monoalphabetic">Monoalphabetic Cipher</option>
            <option value="rowcol">Row-Column Transposition</option>
            <option value="hill">Hill Cipher</option>
            <option value="polyalphabetic">Polyalphabetic Cipher</option>
            <option value="railfence">Rail Fence Cipher</option>
            <option value="otp">One Time Pad</option>
        </select>

        <label for="message">Message:</label>
        <textarea name="message" id="message" rows="4" required></textarea>

        <label for="key">Key (String or JSON for complex keys):</label>
        <textarea name="key" id="key" rows="1" required></textarea>

        <label for="operation">Operation:</label>
        <select name="operation" id="operation" required>
            <option value="encrypt">Encrypt</option>
            <option value="decrypt">Decrypt</option>
        </select>

        <button type="submit">Submit</button>
    </form>
</body>
</html> 


<?php
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $algorithm = $_POST['algorithm'] ?? null;
        $message = $_POST['message'] ?? '';
        $key = $_POST['key'] ?? '';
        $operation = $_POST['operation'] ?? null;
        $result = '';

        switch ($algorithm) {
            case 'caesar':
                if (!is_numeric($key)) {
                    $result = "Invalid key for Caesar Cipher. Must be a number.";
                    break;
                }
                $key = (int)$key;
                $result = $operation === 'encrypt' ? caesarEncrypt($message, $key) : caesarDecrypt($message, $key);
                break;

            case 'playfair':
                $result = $operation === 'encrypt' ? encryptPlayfair($message, $key) : decryptPlayfair($message, $key);
                break;

            case 'monoalphabetic':
                $result = $operation === 'encrypt' ? monoalphabeticEncrypt($message, $key) : monoalphabeticDecrypt($message, $key);
                break;

            case 'rowcol':
                $result = $operation === 'encrypt' ? rowColEncrypt($message, $key) : rowColDecrypt($message, $key);
                break;

            case 'hill':
                
                $result = $operation === 'encrypt' ? hillCipherEncrypt($message, $key) : hillCipherDecrypt($message, $key);
                break;

            case 'polyalphabetic':
                $result = $operation === 'encrypt' ? polyalphabeticEncrypt($message, $key) : polyalphabeticDecrypt($message, $key);
                break;

            case 'railfence':
                $result = $operation === 'encrypt' ? encryptRailFence($message, $key) : decryptRailFence($message, $key);
                break;

            case 'otp':
                $result = $operation === 'encrypt' ? otpEncrypt($message, $key) : otpDecrypt($message, $key);
                break;    

            default:
                $result = "Invalid algorithm selected.";
        }

        echo "<div class='result'><h3>Result:</h3><p>" . htmlspecialchars($result) . "</p></div>";
    }

    // Functions for encryption and decryption

##########################################################################################################################

    // Caesar Cipher
    function caesarEncrypt($message, $shift) {
        $result = "";
        $shift = $shift % 26;
        foreach (str_split($message) as $char) {
            if (ctype_alpha($char)) {
                $offset = ctype_upper($char) ? ord('A') : ord('a');
                $result .= chr((ord($char) - $offset + $shift) % 26 + $offset);
            } else {
                $result .= $char;
            }
        }
        return $result;
    }

    function caesarDecrypt($message, $shift) {
        return caesarEncrypt($message, 26 - ($shift % 26));
    }


##########################################################################################################################

    // Playfair Cipher

    
function preprocessText($text, $isEncrypt = true) {
    $text = strtoupper(preg_replace('/[^A-Za-z]/', '', $text)); // Remove non-alphabetic characters and convert to uppercase
    if ($isEncrypt) {
        $text = str_replace('J', 'I', $text); // Replace 'J' with 'I'
        $processedText = '';
        for ($i = 0; $i < strlen($text); $i++) {
            $processedText .= $text[$i];
            if ($i + 1 < strlen($text) && $text[$i] == $text[$i + 1]) {
                $processedText .= 'X'; // Insert 'X' between repeated characters
            }
        }
        if (strlen($processedText) % 2 != 0) {
            $processedText .= 'X'; // Append 'X' if the length is odd
        }
        return $processedText;
    }
    return $text;
}

function generateKeyMatrix($key) {
    $key = strtoupper(str_replace('J', 'I', $key)); // Replace 'J' with 'I'
    $key = preg_replace('/[^A-Z]/', '', $key); // Remove non-alphabetic characters
    $alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'; // 'J' is omitted
    $uniqueKey = '';
    foreach (str_split($key . $alphabet) as $char) {
        if (strpos($uniqueKey, $char) === false) {
            $uniqueKey .= $char;
        }
    }

    $matrix = [];
    for ($i = 0; $i < 25; $i++) {
        $matrix[floor($i / 5)][($i % 5)] = $uniqueKey[$i];
    }
    return $matrix;
}

function findPosition($matrix, $char) {
    for ($row = 0; $row < 5; $row++) {
        for ($col = 0; $col < 5; $col++) {
            if ($matrix[$row][$col] === $char) {
                return [$row, $col];
            }
        }
    }
    return null;
}

function encryptPlayfair($plaintext, $key) {
    $matrix = generateKeyMatrix($key);
    $plaintext = preprocessText($plaintext, true);

    $ciphertext = '';
    for ($i = 0; $i < strlen($plaintext); $i += 2) {
        $char1 = $plaintext[$i];
        $char2 = $plaintext[$i + 1];
        [$row1, $col1] = findPosition($matrix, $char1);
        [$row2, $col2] = findPosition($matrix, $char2);

        if ($row1 === $row2) {
            // Same row: Shift columns to the right
            $ciphertext .= $matrix[$row1][($col1 + 1) % 5];
            $ciphertext .= $matrix[$row2][($col2 + 1) % 5];
        } elseif ($col1 === $col2) {
            // Same column: Shift rows down
            $ciphertext .= $matrix[($row1 + 1) % 5][$col1];
            $ciphertext .= $matrix[($row2 + 1) % 5][$col2];
        } else {
            // Rectangle: Swap columns
            $ciphertext .= $matrix[$row1][$col2];
            $ciphertext .= $matrix[$row2][$col1];
        }
    }
    return $ciphertext;
}

function decryptPlayfair($ciphertext, $key) {
    $matrix = generateKeyMatrix($key);
    $ciphertext = preprocessText($ciphertext, false);

    $plaintext = '';
    for ($i = 0; $i < strlen($ciphertext); $i += 2) {
        $char1 = $ciphertext[$i];
        $char2 = $ciphertext[$i + 1];
        [$row1, $col1] = findPosition($matrix, $char1);
        [$row2, $col2] = findPosition($matrix, $char2);

        if ($row1 === $row2) {
            // Same row: Shift columns to the left
            $plaintext .= $matrix[$row1][($col1 + 4) % 5];
            $plaintext .= $matrix[$row2][($col2 + 4) % 5];
        } elseif ($col1 === $col2) {
            // Same column: Shift rows up
            $plaintext .= $matrix[($row1 + 4) % 5][$col1];
            $plaintext .= $matrix[($row2 + 4) % 5][$col2];
        } else {
            // Rectangle: Swap columns
            $plaintext .= $matrix[$row1][$col2];
            $plaintext .= $matrix[$row2][$col1];
        }
    }
    return strtolower($plaintext); // Convert to lowercase for better readability
}



    


 ##########################################################################################################################

    // Monoalphabetic Cipher
    // Function to generate a monoalphabetic key based on a keyword
function generateKey($keyword) {
    $alphabet = range('a', 'z');
    $keyword = strtolower($keyword);
    $keywordArray = array_unique(str_split($keyword));
    $remainingLetters = array_diff($alphabet, $keywordArray);
    $key = array_merge($keywordArray, $remainingLetters);
    return $key;
}

// Function to encrypt a plaintext message using the monoalphabetic cipher
function monoalphabeticEncrypt($plaintext, $key) {
    $key = generateKey($key);
    $lowerAlphabet = range('a', 'z');
    $upperAlphabet = range('A', 'Z');
    
    $encryptionMapLower = array_combine($lowerAlphabet, $key);
    $encryptionMapUpper = array_combine($upperAlphabet, array_map('strtoupper', $key));
    
    $ciphertext = '';
    foreach (str_split($plaintext) as $char) {
        if (ctype_lower($char)) {
            $ciphertext .= $encryptionMapLower[$char] ?? $char;
        } elseif (ctype_upper($char)) {
            $ciphertext .= $encryptionMapUpper[$char] ?? $char;
        } else {
            $ciphertext .= $char;
        }
    }
    return $ciphertext;
}

// Function to decrypt a ciphertext message using the monoalphabetic cipher
function monoalphabeticDecrypt($ciphertext, $key) {
    $key = generateKey($key);
    $lowerAlphabet = range('a', 'z');
    $upperAlphabet = range('A', 'Z');
    
    $decryptionMapLower = array_combine($key, $lowerAlphabet);
    $decryptionMapUpper = array_combine(array_map('strtoupper', $key), $upperAlphabet);
    
    $plaintext = '';
    foreach (str_split($ciphertext) as $char) {
        if (ctype_lower($char)) {
            $plaintext .= $decryptionMapLower[$char] ?? $char;
        } elseif (ctype_upper($char)) {
            $plaintext .= $decryptionMapUpper[$char] ?? $char;
        } else {
            $plaintext .= $char;
        }
    }
    return $plaintext;
}
    
 ##########################################################################################################################


    // Row-Column Transposition Cipher

function prepareMatrixforEncrypt($plaintext, $key, $rows, $cols) {
    $plaintextLength = strlen($plaintext);

    // Initialize a 2D array with 'X' as the default value
    $matrix = array_fill(0, $rows, array_fill(0, $cols, 'X'));

    // Fill the matrix row by row using the plaintext
    $index = 0;
    for ($i = 0; $i < $rows; $i++) {
        for ($j = 0; $j < $cols; $j++) {
            if ($index < $plaintextLength) {
                $matrix[$i][$j] = $plaintext[$index++];
            } else {
                $matrix[$i][$j] = 'X'; // Fill the remaining cells with 'X'
            }
        }
    }

    return $matrix;
}

function rowColEncrypt($plaintext, $key) {
    $keyLength = strlen($key);
    $plaintextLength = strlen($plaintext);

    // Step 1: Calculate the number of rows and columns
    $rows = ceil($plaintextLength / $keyLength);
    $cols = $keyLength;

    // Step 2: Prepare the matrix (read the plaintext row by row)
    $matrix = prepareMatrixforEncrypt($plaintext, $key, $rows, $cols);

    // Sort the key characters in ascending order with their indices
    $keyQueue = [];
    for ($i = 0; $i < $keyLength; $i++) {
        $keyQueue[] = [$key[$i], $i];
    }
    usort($keyQueue, function ($a, $b) {
        return $a[0] <=> $b[0];
    });

    // Step 3: Read the matrix column by column to get the ciphertext
    // The column with the smallest key character will be read first
    $ciphertext = "";
    foreach ($keyQueue as $keyData) {
        $col = $keyData[1];
        for ($row = 0; $row < $rows; $row++) {
            $ciphertext .= $matrix[$row][$col];
        }
    }

    return $ciphertext;
}

function prepareMatrixforDecrypt($ciphertext, $key, $rows, $cols) {
    $keyLength = strlen($key);
    $ciphertextLength = strlen($ciphertext);

    // Initialize a 2D array with empty space (' ')
    $matrix = array_fill(0, $rows, array_fill(0, $cols, ' '));

    // Sort the key characters in ascending order with their indices
    $keyQueue = [];
    for ($i = 0; $i < $keyLength; $i++) {
        $keyQueue[] = [$key[$i], $i];
    }
    usort($keyQueue, function ($a, $b) {
        return $a[0] <=> $b[0];
    });

    // Fill the matrix column by column using the ciphertext
    // The column with the smallest key character will be filled first
    $index = 0;
    foreach ($keyQueue as $keyData) {
        $col = $keyData[1];
        for ($row = 0; $row < $rows; $row++) {
            if ($index < $ciphertextLength) {
                $matrix[$row][$col] = $ciphertext[$index++];
            } else {
                $matrix[$row][$col] = 'X'; // Fill the remaining cells with 'X'
            }
        }
    }

    return $matrix;
}

function rowColDecrypt($ciphertext, $key) {
    $keyLength = strlen($key);
    $ciphertextLength = strlen($ciphertext);

    // Step 1: Calculate the number of rows and columns
    $rows = ceil($ciphertextLength / $keyLength);
    $cols = $keyLength;

    // Step 2: Prepare the matrix (read the ciphertext column by column)
    $matrix = prepareMatrixforDecrypt($ciphertext, $key, $rows, $cols);

    // Step 3: Read the matrix row by row to get the plaintext
    $plaintext = "";
    for ($i = 0; $i < $rows; $i++) {
        for ($j = 0; $j < $cols; $j++) {
            $plaintext .= $matrix[$i][$j];
        }
    }

    return $plaintext;
}



##########################################################################################################################

    
// Polyalphabetic Cipher (Vigenère Cipher)

function polyalphabeticEncrypt($plaintext, $key) {
    $plaintext = strtoupper($plaintext);
    $key = strtoupper($key);
    $keyIndex = 0;
    $keyLength = strlen($key);
    $ciphertext = '';

    foreach (str_split($plaintext) as $char) {
        if (ctype_alpha($char)) {
            $shift = ord($key[$keyIndex % $keyLength]) - ord('A');
            $offset = ctype_upper($char) ? ord('A') : ord('a');
            $ciphertext .= chr((ord($char) - $offset + $shift) % 26 + $offset);
            $keyIndex++;
        } else {
            $ciphertext .= $char;
        }
    }

    return $ciphertext;
}

function polyalphabeticDecrypt($ciphertext, $key) {
    $ciphertext = strtoupper($ciphertext);
    $key = strtoupper($key);
    $keyIndex = 0;
    $keyLength = strlen($key);
    $plaintext = '';

    foreach (str_split($ciphertext) as $char) {
        if (ctype_alpha($char)) {
            $shift = ord($key[$keyIndex % $keyLength]) - ord('A');
            $offset = ctype_upper($char) ? ord('A') : ord('a');
            $plaintext .= chr((ord($char) - $offset - $shift + 26) % 26 + $offset);
            $keyIndex++;
        } else {
            $plaintext .= $char;
        }
    }

    return $plaintext;
}


##########################################################################################################################
    
//HILL CIPHER


function mod($a, $b) {
    return ($a % $b + $b) % $b;
}

function matrixModInverse($matrix, $mod) {
    $det = $matrix[0][0] * $matrix[1][1] - $matrix[0][1] * $matrix[1][0];
    $det = mod($det, $mod);
    $detInv = -1;
    for ($i = 0; $i < $mod; $i++) {
        if (mod($det * $i, $mod) == 1) {
            $detInv = $i;
            break;
        }
    }
    if ($detInv == -1) {
        return null; // Matrix is not invertible
    }

    $adj = [
        [ $matrix[1][1], -$matrix[0][1] ],
        [ -$matrix[1][0], $matrix[0][0] ]
    ];

    $inverse = [];
    foreach ($adj as $row) {
        $inverseRow = [];
        foreach ($row as $value) {
            $inverseRow[] = mod($value * $detInv, $mod);
        }
        $inverse[] = $inverseRow;
    }

    return $inverse;
}

function parseKey($key) {
    $size = sqrt(strlen($key));
    if ($size != floor($size)) {
        throw new Exception("Invalid key length. Key must form a square matrix.");
    }

    $matrix = [];
    $keyIndex = 0;
    for ($i = 0; $i < $size; $i++) {
        $row = [];
        for ($j = 0; $j < $size; $j++) {
            $char = strtoupper($key[$keyIndex++]);
            $row[] = ord($char) - ord('A'); // Convert letter to zero-indexed position
        }
        $matrix[] = $row;
    }

    return $matrix;
}

function preprocessText_hill($text) {
    // Remove spaces and non-alphabetic characters, and convert to uppercase
    $text = strtoupper(preg_replace('/[^A-Za-z]/', '', $text));
    return $text;
}

function hillCipherEncrypt($plaintext, $key) {
    $matrix = parseKey($key);
    $size = count($matrix);

    $plaintext = preprocessText_hill($plaintext);

    while (strlen($plaintext) % $size != 0) {
        $plaintext .= 'X'; // Padding with 'X'
    }

    $textVector = [];
    foreach (str_split($plaintext) as $char) {
        $textVector[] = ord($char) - ord('A');
    }

    $ciphertext = '';
    for ($i = 0; $i < count($textVector); $i += $size) {
        $chunk = array_slice($textVector, $i, $size);
        $encryptedChunk = array_fill(0, $size, 0);

        for ($row = 0; $row < $size; $row++) {
            for ($col = 0; $col < $size; $col++) {
                $encryptedChunk[$row] += $matrix[$row][$col] * $chunk[$col];
            }
            $encryptedChunk[$row] = mod($encryptedChunk[$row], 26);
        }

        foreach ($encryptedChunk as $value) {
            $ciphertext .= chr($value + ord('A'));
        }
    }

    return $ciphertext;
}

function hillCipherDecrypt($ciphertext, $key) {
    $matrix = parseKey($key);
    $size = count($matrix);

    $inverseMatrix = matrixModInverse($matrix, 26);
    if ($inverseMatrix === null) {
        throw new Exception("Key matrix is not invertible under mod 26.");
    }

    $ciphertext = preprocessText_hill($ciphertext);

    $cipherVector = [];
    foreach (str_split($ciphertext) as $char) {
        $cipherVector[] = ord($char) - ord('A');
    }

    $plaintext = '';
    for ($i = 0; $i < count($cipherVector); $i += $size) {
        $chunk = array_slice($cipherVector, $i, $size);
        $decryptedChunk = array_fill(0, $size, 0);

        for ($row = 0; $row < $size; $row++) {
            for ($col = 0; $col < $size; $col++) {
                $decryptedChunk[$row] += $inverseMatrix[$row][$col] * $chunk[$col];
            }
            $decryptedChunk[$row] = mod($decryptedChunk[$row], 26);
        }

        foreach ($decryptedChunk as $value) {
            $plaintext .= chr($value + ord('A'));
        }
    }

    return strtolower($plaintext);
}









##########################################################################################################################

    //Reil Fence Cipher
    function encryptRailFence($message, $num_rails) {
        if ($num_rails <= 1) return $message;
    
        $rails = array_fill(0, $num_rails, '');
        $row = 0;
        $down = true;
    
        foreach (str_split($message) as $char) {
            $rails[$row] .= $char;
            $row += $down ? 1 : -1;
            if ($row == 0 || $row == $num_rails - 1) $down = !$down;
        }
    
        return implode('', $rails);
    }
    
    function decryptRailFence($ciphertext, $num_rails) {
        if ($num_rails <= 1) return $ciphertext;
    
        $length = strlen($ciphertext);
        $rails = array_fill(0, $num_rails, array_fill(0, $length, ''));
        $row = 0;
        $down = true;
    
        for ($i = 0; $i < $length; $i++) {
            $rails[$row][$i] = '*';
            $row += $down ? 1 : -1;
            if ($row == 0 || $row == $num_rails - 1) $down = !$down;
        }
    
        $index = 0;
        foreach ($rails as &$rail) {
            foreach ($rail as &$cell) {
                if ($cell == '*') $cell = $ciphertext[$index++];
            }
        }
    
        $result = '';
        $row = 0;
        $down = true;
    
        for ($i = 0; $i < $length; $i++) {
            $result .= $rails[$row][$i];
            $row += $down ? 1 : -1;
            if ($row == 0 || $row == $num_rails - 1) $down = !$down;
        }
    
        return $result;
    }


    #################################################################################################################################

    // one time pad

    

// Encryption function using user-provided key
function otpEncrypt($msg, $key) {
    if (strlen($msg) != strlen($key)) {
        echo "Error: The key length must be the same as the message length.\n";
        return;
    }

    $cipher_msg = "";

    for ($i = 0; $i < strlen($msg); $i++) {
        $char = $msg[$i];
        if (ctype_lower($char)) {
            $cipher_msg .= chr(((ord($char) - 97 + ord($key[$i]) - 97) % 26) + 97);
        } elseif (ctype_upper($char)) {
            $cipher_msg .= chr(((ord($char) - 65 + ord($key[$i]) - 65) % 26) + 65);
        } else {
            $cipher_msg .= $char;  // for spaces and special chars
        }
    }

    return $cipher_msg;
}

// Decryption function using the provided key
function otpDecrypt($msg, $key) {
    if (strlen($msg) != strlen($key)) {
        echo "Error: The key length must be the same as the message length.\n";
        return;
    }

    $original_message = "";

    for ($i = 0; $i < strlen($msg); $i++) {
        $char = $msg[$i];
        if (ctype_lower($char)) {
            $original_message .= chr(((ord($char) - 97 - (ord($key[$i]) - 97)) % 26) + 97);
        } elseif (ctype_upper($char)) {
            $original_message .= chr(((ord($char) - 65 - (ord($key[$i]) - 65)) % 26) + 65);
        } else {
            $original_message .= $char;  // for spaces and special chars
        }
    }

    return $original_message;
}


    
    ?>







    
