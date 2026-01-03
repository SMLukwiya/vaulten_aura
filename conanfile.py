from conan import ConanFile
from conan.tools.cmake import CMakeToolchain, CMake, cmake_layout, CMakeDeps
import os

class vaultenAuraRecipe(ConanFile):
    name = "vaulten_aura"
    version = "1.0.0"

    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False], "fPIC": [True, False]}
    default_options={"shared": False, "fPIC": True}

    #dependencies
    def requirements(self):
        self.requires("openssl/3.5.2")
        self.requires("quickjs/2024-01-13")
        self.requires("wasmtime/31.0.0")
        self.requires("picotls/2025-07-16")
        self.requires("yaml/0.2.5")

    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()
        tc = CMakeToolchain(self)
        tc.user_presets_path = 'ConanPresets.json'
        tc.generate()

    def build_requirements(self):
        self.tool_requires("cmake/[>=3.23 <4]")

    def layout(self):
        cmake_layout(self)

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()
        cmake.test()
