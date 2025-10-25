cmake_minimum_required(VERSION 3.15)
project(PSI C)

# ==============================
# 🔧 项目配置
# ==============================

# 自动导出 compile_commands.json 供 clangd 使用
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# C 标准
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# ==============================
# 📦 查找依赖库
# ==============================

# macOS Homebrew 路径配置
if(APPLE)
    set(HOMEBREW_PREFIX "/opt/homebrew")
    
    # OpenMP
    set(OpenMP_C_FLAGS "-Xpreprocessor -fopenmp")
    set(OpenMP_C_LIB_NAMES "omp")
    set(OpenMP_omp_LIBRARY "${HOMEBREW_PREFIX}/opt/libomp/lib/libomp.dylib")
    include_directories("${HOMEBREW_PREFIX}/opt/libomp/include")
    
    # GMP
    include_directories("${HOMEBREW_PREFIX}/opt/gmp/include")
    link_directories("${HOMEBREW_PREFIX}/opt/gmp/lib")
    
    # OpenSSL
    include_directories("${HOMEBREW_PREFIX}/opt/openssl/include")
    link_directories("${HOMEBREW_PREFIX}/opt/openssl/lib")
endif()

find_package(OpenMP REQUIRED)

# ==============================
# 📝 源文件列表
# ==============================

set(SOURCES
    main.c
    PSI.c
    PSI_Cloud.c
    client.c
    Verify.c
    Beaver_Cloud.c
    beaver.c
    bucket.c
    crt_gmp.c
    crypt.c
    dataset.c
    fft_poly.c
    hash.c
    modsystem.c
)

set(HEADERS
    PSI.h
    PSI_Cloud.h
    client.h
    Verify.h
    Beaver_Cloud.h
    beaver.h
    bucket.h
    crt_gmp.h
    crypt.h
    dataset.h
    fft_poly.h
    hash.h
    modsystem.h
)

# ==============================
# 🎯 可执行文件目标
# ==============================

add_executable(psi_program ${SOURCES} ${HEADERS})

# ==============================
# ⚙️ 编译选项
# ==============================

# 通用编译选项
target_compile_options(psi_program PRIVATE
    -Wall
    -O1
    -g
)

# AddressSanitizer
target_compile_options(psi_program PRIVATE
    -fsanitize=address
    -fno-omit-frame-pointer
    -fno-optimize-sibling-calls
)

# OpenMP
target_compile_options(psi_program PRIVATE
    ${OpenMP_C_FLAGS}
)

# ==============================
# 🔗 链接库
# ==============================

target_link_libraries(psi_program PRIVATE
    gmp
    crypto
    ssl
    m
    pthread
    ${OpenMP_omp_LIBRARY}
)

# AddressSanitizer 链接选项
target_link_options(psi_program PRIVATE
    -fsanitize=address
)

# ==============================
# 🐞 调试目标
# ==============================

add_executable(psi_program_debug ${SOURCES} ${HEADERS})

target_compile_options(psi_program_debug PRIVATE
    -Wall
    -O0
    -g
    -fsanitize=address
    -fno-omit-frame-pointer
    -fno-optimize-sibling-calls
    ${OpenMP_C_FLAGS}
)

target_link_libraries(psi_program_debug PRIVATE
    gmp
    crypto
    ssl
    m
    pthread
    ${OpenMP_omp_LIBRARY}
)

target_link_options(psi_program_debug PRIVATE
    -fsanitize=address
)

# ==============================
# 📄 安装配置
# ==============================

install(TARGETS psi_program
    RUNTIME DESTINATION bin
)

# ==============================
# 💡 提示信息
# ==============================

message(STATUS "🔧 PSI 项目配置完成")
message(STATUS "📦 输出目录: ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
message(STATUS "📝 compile_commands.json 将生成在构建目录")
message(STATUS "")
message(STATUS "💡 构建步骤:")
message(STATUS "   mkdir -p build && cd build")
message(STATUS "   cmake ..")
message(STATUS "   make -j$(nproc)")
message(STATUS "")
message(STATUS "💡 运行前请设置:")
message(STATUS "   export ASAN_OPTIONS=fast_unwind_on_malloc=0:malloc_context_size=50")


