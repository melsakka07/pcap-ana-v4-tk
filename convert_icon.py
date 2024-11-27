from PIL import Image
import os

def convert_png_to_ico():
    png_file = 'android-chrome-120x120.png'
    ico_file = 'app_icon.ico'
    
    if not os.path.exists(png_file):
        print(f"Error: {png_file} not found!")
        return False
        
    try:
        img = Image.open(png_file)
        img.save(ico_file, format='ICO')
        print(f"Successfully converted {png_file} to {ico_file}")
        return True
    except Exception as e:
        print(f"Error converting icon: {str(e)}")
        return False

if __name__ == "__main__":
    convert_png_to_ico() 