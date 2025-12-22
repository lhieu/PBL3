cd "/Users/lvh/Documents/Arduino/PBL3/book-567/device_firmware/6_project_optimize"
rm -rf build managed_components dependencies.lock
idf.py reconfigure
idf.py build

Cụ thể, những chỗ hay “dính” path cũ nhất là:

build/ (cache CMake + cấu hình IDF)

managed_components/ (component đã resolve/tải trước đó)

dependencies.lock (lock dependency đã chốt từ lần trước)


cd /path/to/project
rm -rf build managed_components dependencies.lock
idf.py reconfigure
idf.py build

gặp lỗi path đang bám vào dường dẫn cũ chạy lệnh này để xóa đường dẫn cũ path đang bám vào 