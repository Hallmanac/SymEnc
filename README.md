SymEnc
======

Single class used to handle symmetric encryption for a given application. The actual class is located under /src/SymEnc.Core/SymmetricEncryptionSvc.cs if you just want to copy and paste the contents into your own solution.

Simply add this class into your project and change the const Default256BitKey by using the console application in this solution. The console application uses the SymmetricEncryptionSvc class to generate a new cryptographically random 256 bit key.
