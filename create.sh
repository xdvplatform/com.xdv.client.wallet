rm -rf target/native
mkdir -p target/native
cd target/native
jar -xvf ../build/libs/wallet-1.0.0.jar >/dev/null 2>&1
cp -R META-INF BOOT-INF/classes
native-image -H:Name=wallet -cp BOOT-INF/classes:`find BOOT-INF/lib | tr '\n' ':'`
mv wallet ../