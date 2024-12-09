﻿# NT140.P11-NetworkScanner

Adabnet là một công cụ quét mạng mạnh mẽ, cho phép bạn kiểm tra, quét các thiết bị, dịch vụ, subdomains, lỗ hổng bảo mật và nhiều tính năng khác trong một mạng. Công cụ này sử dụng nhiều phương pháp quét và phân tích khác nhau, bao gồm quét DNS, quét MAC, quét subdomain, quét lỗ hổng bảo mật và giám sát mạng với Wireshark.

Tính năng chính
Quét Subdomain: Tìm kiếm tất cả các subdomains của một domain.
Quét DNS: Kiểm tra các bản ghi DNS của một domain.
Quét Lỗ Hổng Bảo Mật: Quét các lỗ hổng bảo mật sử dụng Shodan API.
Truy Vết Đường Đi Gói Tin (Traceroute): Xác định đường đi của gói tin qua mạng.
Quét Các Thiết Bị Kết Nối: Tìm các thiết bị kết nối vào mạng của bạn.
Giám Sát Mạng Với Wireshark: Giám sát gói tin mạng theo thời gian thực.
Quét Thư Mục Website: Dùng dirbuster để tìm các thư mục ẩn trên website.
Quản Lý Bản Quyền API: Hệ thống quản lý và mã hóa API key để kích hoạt tính năng enterprise.

Cấu Trúc Thư Mục
Dưới đây là cấu trúc thư mục của dự án:
**\_ ** \_\_ ** \_\_\_**  
 / | \_**_/ /_** _/ /_ \_**\_ \_** / /\_ / **\_/**\_\_\_**** **\_** **\_ \_\_\_**
/ /| |/ ** / ** `/ __ \/ __ \/ _ \/ __/   \__ \/ ___/ __ `/ ** \/ _ \/ _**/
/ **_ / /_/ / /_/ / /_/ / / / / **/ /\_ **\_/ / /**/ /_/ / / / / \_\_/ /  
/_/ |\_\__,_/\__,_/\_.**_/_/ /\_/\_**/\_\_/ /\_**\_/\_**/\__,_/_/ /_/\_\__/_/

NetworkScanner/
├── scanner/ # 🛠️ Các công cụ quét siêu mạnh mẽ!
│ ├── **init**.py # 👷‍♂️ File khởi tạo module (rỗng), mở đầu cho cuộc hành trình quét!
│ ├── cli.py # 📡 Các lệnh siêu dễ thương để bạn chạy trên dòng lệnh (command-line arguments)
│ ├── core.py # 🧠 Bộ não của dự án, chứa các chức năng chính như quét dịch vụ, ping, ARP
│ ├── dns_scanner.py # 🌐 Quét DNS như một chuyên gia, đi tìm mọi bản ghi DNS!
│ ├── specialized_scan.py # 🔍 Các quét chuyên sâu cho những kẻ thích mạo hiểm
│ ├── auth_scanner.py # 🔐 Quét bảo mật để kiểm tra mọi lỗ hổng bảo mật
│ ├── mac_scanner.py # 🖥️ Quét địa chỉ MAC, biết ai đang chơi cùng mạng với bạn
│ ├── thank_you.py # ❤️ Cảm ơn vì đã sử dụng công cụ tuyệt vời này!
│ ├── dirbuster.py # 🚪 Quét thư mục, tìm mọi ngóc ngách của website
│ ├── device_scanner.py # 📱 Quét các thiết bị kết nối trong mạng, có thể tìm thấy thiết bị ẩn!
│ ├── subdomain_scanner.py # 🏰 Quét các subdomain của domain, khám phá những vùng đất mới
│ ├── vuln_scanner.py # 🔥 Quét lỗ hổng bảo mật với Shodan, đừng để chúng trốn thoát!
│ ├── whois_scanner.py # 🕵️‍♂️ Tìm kiếm thông tin WHOIS của các domain
│ ├── traceroute_scanner.py # 🌍 Truy vết đường đi của gói tin, từ bạn đến thế giới!
│ ├── wireshark_scanner.py # 🐳 Quét mạng với Wireshark, khám phá mọi gói tin!
│ ├── license_manager.py # 🛡️ Quản lý bản quyền API, giúp bạn giữ an toàn với API keys
│ └── utils.py # ⚙️ Các hàm tiện ích hỗ trợ, giúp công việc trở nên dễ dàng hơn
│
├── server/
│ ├── create_secret_key.py # 🔑 Khởi tạo sercet.key
│ └── server.py # 🔒 Server xác nhận key
│
├── wordlists/ # 📚 Thư mục Wordlists
│ ├── directory-list-1.0.txt  
│ ├── directory-list-2.3-small.txt  
│ └── directory-list-2.3-medium.txt
│
├── tests/   
│ └─ test_core.py # ⚙️ Kiểm tra công cụ
│
├── folder_tree.txt # Cấu trúc thư mục của dự án (Bạn đang ở đây 📍)
├── main.py # 🚀 Điểm bắt đầu của hành trình quét mạng, hãy khởi động!
├── requirements.txt # 📜 Các thứ bạn cần cài đặt để làm cho mọi thứ hoạt động
├── license.key # 🔑 Bí mật API key của bạn (đừng làm mất nhé!)
├── secret.key # 🔒 Khóa bảo mật dùng để mã hóa API key
└── README.md # 📚 Tài liệu hướng dẫn bạn cách làm mọi thứ (đừng bỏ qua nhé!)

Cài đặt và yêu cầu hệ thống
Yêu cầu hệ thống:
Python 3.6+
Thư viện yêu cầu:
requests: Để gửi yêu cầu HTTP cho API và quét lỗ hổng.
python-whois: Để lấy thông tin WHOIS.
pyshark: Để giám sát mạng với Wireshark.
colorama: Để tạo màu sắc đẹp cho giao diện người dùng trên terminal.
shodan: Để quét lỗ hổng bảo mật qua Shodan.
cryptography: Để mã hóa và giải mã API key.
Cài đặt thư viện:
Cài đặt các thư viện yêu cầu với lệnh:

bash
Copy code
pip install -r requirements.txt
Cài đặt Wireshark:
Công cụ này yêu cầu Wireshark và Tshark phải được cài đặt. Bạn có thể cài đặt Wireshark bằng cách sử dụng apt (trên hệ điều hành Ubuntu/Debian):

sudo apt-get install wireshark tshark
Cài đặt Shodan API:
Bạn cần một Shodan API key để sử dụng tính năng quét lỗ hổng bảo mật. Truy cập Shodan để lấy API key của bạn.

Cài đặt và sử dụng License:
License file: Khi bạn chạy chương trình lần đầu tiên với tính năng enterprise, bạn sẽ được yêu cầu nhập API key và mã hóa nó vào tệp license.key.
Cách sử dụng
Kích hoạt Bản Quyền Enterprise:
Nếu bạn chưa có bản quyền enterprise, chương trình sẽ yêu cầu nhập API key:

bash
Copy code
python main.py --enterprise
Các tính năng chính:
Quét Subdomain: Quét các subdomains của domain và kiểm tra chúng:

bash
Copy code
python main.py --scan-subdomains example.com --wordlist wordlist.txt
Quét DNS: Quét các bản ghi DNS của domain:

bash
Copy code
python main.py --dns example.com
Quét Lỗ Hổng Bảo Mật (Shodan): Quét lỗ hổng bảo mật của một host:

bash
Copy code
python main.py --vuln-scan example.com
Traceroute: Xem đường đi của gói tin đến host:

bash
Copy code
python main.py --traceroute example.com
Giám sát Mạng (Wireshark): Giám sát gói tin mạng trực tiếp từ interface:

bash
Copy code
sudo python main.py --wireshark eth0
Quét Các Thiết Bị Kết Nối: Quét các thiết bị trong mạng của bạn:

bash
Copy code
python main.py --scan-devices 192.168.1.0/24
Quét Thư Mục Website (Dirbuster): Quét các thư mục ẩn của website:

bash
Copy code
python main.py --dirbust example.com wordlist.txt
WHOIS: Lấy thông tin WHOIS của một domain:

bash
Copy code
python main.py --whois example.com
Tìm Địa Chỉ MAC: Tìm địa chỉ MAC của một thiết bị:

bash
Copy code
python main.py --get-mac 192.168.1.100
Cảm ơn và Liên hệ
Cảm ơn bạn đã sử dụng NetworkScanner! Nếu bạn có bất kỳ câu hỏi nào hoặc muốn đóng góp cho dự án, đừng ngần ngại liên hệ với chúng tôi hoặc tạo một issue trên GitHub.

Chúng tôi luôn sẵn lòng nhận phản hồi và cải tiến công cụ này để giúp bạn làm việc hiệu quả hơn! 🚀

Giấy phép
Dự án này được cấp phép dưới Giấy phép MIT.
