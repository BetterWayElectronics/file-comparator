# BwE File Comparator

![BwE](https://i.imgur.com/InoWRCr.png)

Tool for analysing and comparing files (in bulk) but is mainly intended for binary files (firmware flashes, executables, malware etc).

Performs the following functions:

## Comparative Analysis
1. Compare Offsets (Hex) (Result - Filename)
2. Compare Offsets (ASCII) (Result - Filename)
3. Compare Offsets MD5 (MD5 Hash - Filename)
4. Dual Offsets Comparison (Result 1 - Result 2 - Filename)
5. Dual Offsets MD5 Comparison (MD5 Hash 1 - MD5 Hash 2 - Filename)
6. Dynamic Offset MD5 Calculation (Size Header - MD5 - Filename)

## Statistical Analysis
7. Compare Offsets Entropy (log2(256)) (Entropy - Filename)
8. Compare Offsets Statistics (00 Count % / FF Count % - Filename)
9. Compare File Entropy (log2(256)) (Entropy - Filename)
10. Compare File Statistics (00 Count % / FF Count % - Filename)

## Hash
11. Obtain File MD5s (MD5 Hash - Filename)
12. Obtain File SHA1s (SHA1 Hash - Filename)
13. Obtain MIME Types (MIME - Filename)

## Other
14. Extract File By Offset (/Extracted/Hash)
