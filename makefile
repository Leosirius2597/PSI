# ==============================
# 🔧 PSI 项目 Makefile (ASan 友好版)
# ==============================

# 编译器
CC      := gcc

# 输出目录（可通过命令行覆盖：make OUTPUT_DIR=output）
OUTPUT_DIR ?= .

# 目标文件
TARGET  := psi_program

# 所有源文件（自动搜索当前目录下的 .c）
SRC     := $(wildcard *.c)

# 对应的目标文件 (.o)，输出到 OUTPUT_DIR
OBJ     := $(patsubst %.c,$(OUTPUT_DIR)/%.o,$(SRC))

# ==============================
# ⚙️ 通用编译和链接选项
# ==============================

# AddressSanitizer 基本标志（编译 + 链接都需要）
ASAN_FLAGS := -fsanitize=address -fno-omit-frame-pointer -fno-optimize-sibling-calls

# macOS OpenMP 配置 (使用 Homebrew 安装的 libomp)
OPENMP_FLAGS := -Xpreprocessor -fopenmp -I/opt/homebrew/opt/libomp/include
OPENMP_LIBS  := -L/opt/homebrew/opt/libomp/lib -lomp

# macOS Homebrew 库路径配置
BREW_INCLUDE := -I/opt/homebrew/opt/gmp/include -I/opt/homebrew/opt/openssl/include
BREW_LIBS    := -L/opt/homebrew/opt/gmp/lib -L/opt/homebrew/opt/openssl/lib

# 编译选项
CFLAGS  := -Wall -O1 -g $(OPENMP_FLAGS) $(BREW_INCLUDE) -I. $(ASAN_FLAGS)
LDFLAGS := -lgmp -lcrypto -lssl -lm -lpthread $(OPENMP_LIBS) $(BREW_LIBS) $(ASAN_FLAGS)

# 调试模式（make debug）
DEBUGFLAGS := -g -O0 -Wall $(OPENMP_FLAGS) $(BREW_INCLUDE) -I. $(ASAN_FLAGS)

# ==============================
# 🏗️ 默认规则
# ==============================

$(OUTPUT_DIR)/$(TARGET): $(OBJ)
	@echo "🔗 正在链接目标文件..."
	$(CC) $(OBJ) -o $(OUTPUT_DIR)/$(TARGET) $(LDFLAGS)
	@echo "✅ 编译完成: $(OUTPUT_DIR)/$(TARGET)"
	@echo ""
	@echo "💡 提示: 为了显示完整释放栈帧，请运行前设置："
	@echo "    export ASAN_OPTIONS=fast_unwind_on_malloc=0:malloc_context_size=50"
	@echo ""

# ==============================
# 🧩 编译每个 .c 文件为 .o
# ==============================

$(OUTPUT_DIR)/%.o: %.c | $(OUTPUT_DIR)
	@echo "🧱 编译源文件: $<"
	$(CC) $(CFLAGS) -c $< -o $@

# 确保输出目录存在
$(OUTPUT_DIR):
	@mkdir -p $(OUTPUT_DIR)

# ==============================
# 🧹 清理目标文件
# ==============================

.PHONY: clean debug install

clean:
	@echo "🧹 正在清理..."
	rm -f $(OBJ) $(OUTPUT_DIR)/$(TARGET) $(OUTPUT_DIR)/$(TARGET)_debug
	rm -f *.o $(TARGET) $(TARGET)_debug
	@echo "✅ 清理完成"

# ==============================
# 🐞 调试模式
# ==============================

debug: | $(OUTPUT_DIR)
	@echo "🐞 使用调试编译选项 (ASan + 完整堆栈)..."
	$(CC) $(SRC) -o $(OUTPUT_DIR)/$(TARGET)_debug $(DEBUGFLAGS) $(LDFLAGS)
	@echo "✅ 生成调试版本: $(OUTPUT_DIR)/$(TARGET)_debug"
	@echo ""
	@echo "💡 提示: 运行前请执行："
	@echo "    export ASAN_OPTIONS=fast_unwind_on_malloc=0:malloc_context_size=50"
	@echo ""

# ==============================
# 📦 安装 (可选)
# ==============================

install:
	@echo "📦 安装到 /usr/local/bin..."
	sudo cp $(OUTPUT_DIR)/$(TARGET) /usr/local/bin/
