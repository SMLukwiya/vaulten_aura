from conan import ConanFile
from conan.tools.cmake import CMakeToolchain, cmake_layout, CMakeDeps
from conan.tools.files import copy
import os

class vaultenAuraRecipe(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False], "fPIC": [True, False]}
    default_options={"shared": False, "fPIC": True}

    #dependencies
    def requirements(self):
        self.requires("openssl/3.5.2")
        self.requires("quickjs/2024-01-13")
        self.requires("wasmtime/31.0.0")
        self.requires("libcurl/8.15.0")
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
