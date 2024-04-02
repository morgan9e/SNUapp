NDK="$HOME/Downloads/android-ndk-r26c-linux/android-ndk-r26c/toolchains/llvm/prebuilt/linux-x86_64"
#$NDK/bin/aarch64-linux-android28-clang++ -c com_ubivelox_security_EncryptionKeyStore.cpp -fPIC -static-libstdc++ -o eks.o; 
#$NDK/bin/aarch64-linux-android28-clang++ -static-libstdc++ -shared -o a.so eks.o
$NDK/bin/aarch64-linux-android28-clang++ -fPIC -shared -llog -static-libstdc++ -o a.so com_ubivelox_security_EncryptionKeyStore.cpp
mv a.so $HOME/Lab/SNUapp/SNUapp_modified/SNUapp/lib/arm64-v8a/libEncryptionKeyStore.so

java -jar $HOME/.apklab/apktool_2.9.3.jar b $HOME/Lab/SNUapp/SNUapp_modified/SNUapp --use-aapt2; 
java -jar $HOME/.apklab/uber-apk-signer-1.3.0.jar -a $HOME/Lab/SNUapp/SNUapp_modified/SNUapp/dist/SNUapp.apk --allowResign --overwrite; 
adb install -r $HOME/Lab/SNUapp/SNUapp_modified/SNUapp/dist/SNUapp.apk
