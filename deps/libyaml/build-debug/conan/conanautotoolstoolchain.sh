script_folder="/home/lukwiya/studies/C/vaulten_aura/deps/libyaml/build-debug/conan"
echo "echo Restoring environment" > "$script_folder/deactivate_conanautotoolstoolchain.sh"
for v in CPPFLAGS CXXFLAGS CFLAGS LDFLAGS PKG_CONFIG_PATH
do
    is_defined="true"
    value=$(printenv $v) || is_defined="" || true
    if [ -n "$value" ] || [ -n "$is_defined" ]
    then
        echo export "$v='$value'" >> "$script_folder/deactivate_conanautotoolstoolchain.sh"
    else
        echo unset $v >> "$script_folder/deactivate_conanautotoolstoolchain.sh"
    fi
done


export CPPFLAGS="$CPPFLAGS"
export CXXFLAGS="$CXXFLAGS -std=gnu++17 -m64 -g"
export CFLAGS="$CFLAGS -m64 -g"
export LDFLAGS="$LDFLAGS -m64"
export PKG_CONFIG_PATH="$script_folder/../../build-debug/conan:$PKG_CONFIG_PATH"