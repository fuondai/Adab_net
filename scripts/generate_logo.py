from PIL import Image, ImageDraw, ImageFont
import os

def create_logo():
    # Tạo ảnh với nền trong suốt
    width = 500
    height = 500
    image = Image.new('RGBA', (width, height), (255, 255, 255, 0))
    draw = ImageDraw.Draw(image)
    
    # Vẽ shield shape
    shield_points = [
        (width//4, height//8),  # Top
        (3*width//4, height//8),  # Top right
        (3*width//4, 3*height//4),  # Bottom right
        (width//2, 7*height//8),  # Bottom point
        (width//4, 3*height//4),  # Bottom left
    ]
    draw.polygon(shield_points, fill=(65, 105, 225, 230))  # Royal Blue
    
    # Thêm text
    try:
        font = ImageFont.truetype("arial.ttf", 60)
    except:
        font = ImageFont.load_default()
        
    draw.text((width//2, height//2), "AdabNet", 
              font=font, fill=(255, 255, 255, 255),
              anchor="mm")
    
    # Tạo thư mục nếu chưa tồn tại
    os.makedirs('docs/images', exist_ok=True)
    
    # Lưu ảnh
    image.save('docs/images/logo.png')

if __name__ == "__main__":
    create_logo() 