# ==============================
# 🔧 PSI 项目 Makefile (ASan 友好版)
# ==============================

# 编译器
CC      := gcc

# 目标文件
TARGET  := psi_program

# 所有源文件（自动搜索当前目录下的 .c）
SRC     := $(wildcard *.c)

# 对应的目标文件 (.o)
OBJ     := $(SRC:.c=.o)

# ==============================
# ⚙️ 通用编译和链接选项
# ==============================

# AddressSanitizer 基本标志（编译 + 链接都需要）
ASAN_FLAGS := -fsanitize=address -fno-omit-frame-pointer -fno-optimize-sibling-calls

# 编译选项
CFLAGS  := -Wall -O1 -g -fopenmp -I. $(ASAN_FLAGS)
LDFLAGS := -lgmp -lcrypto -lssl -lm -lpthread -lgomp $(ASAN_FLAGS)

# 调试模式（make debug）
DEBUGFLAGS := -g -O0 -Wall -I. $(ASAN_FLAGS)

# ==============================
# 🏗️ 默认规则
# ==============================

$(TARGET): $(OBJ)
	@echo "🔗 正在链接目标文件..."
	$(CC) $(OBJ) -o $(TARGET) $(LDFLAGS)
	@echo "✅ 编译完成: $(TARGET)"
	@echo ""
	@echo "💡 提示: 为了显示完整释放栈帧，请运行前设置："
	@echo "    export ASAN_OPTIONS=fast_unwind_on_malloc=0:malloc_context_size=50"
	@echo ""

# ==============================
# 🧩 编译每个 .c 文件为 .o
# ==============================

%.o: %.c
	@echo "🧱 编译源文件: $<"
	$(CC) $(CFLAGS) -c $< -o $@

# ==============================
# 🧹 清理目标文件
# ==============================

.PHONY: clean debug install

clean:
	@echo "🧹 正在清理..."
	rm -f $(OBJ) $(TARGET) $(TARGET)_debug
	@echo "✅ 清理完成"

# ==============================
# 🐞 调试模式
# ==============================

debug:
	@echo "🐞 使用调试编译选项 (ASan + 完整堆栈)..."
	$(CC) $(SRC) -o $(TARGET)_debug $(DEBUGFLAGS) $(LDFLAGS)
	@echo "✅ 生成调试版本: $(TARGET)_debug"
	@echo ""
	@echo "💡 提示: 运行前请执行："
	@echo "    export ASAN_OPTIONS=fast_unwind_on_malloc=0:malloc_context_size=50"
	@echo ""

# ==============================
# 📦 安装 (可选)
# ==============================

install:
	@echo "📦 安装到 /usr/local/bin..."
	sudo cp $(TARGET) /usr/local/bin/
