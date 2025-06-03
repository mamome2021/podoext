#!/usr/bin/env python3
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, wait
from itertools import repeat
import multiprocessing
from pathlib import Path
import signal
import sys
import traceback
import urllib.parse

import httpx

class ExtractorNoChapterBase(ABC):

    # Override this for setting extension of downloaded images
    image_extension = None

    help_text_basic = '''用法：
{0} {1}
{0} list-comic
    列出已購漫畫
{0} dl [-o 下載位置] COMIC_ID CHAPTER_ID ...
    下載漫畫。COMIC_ID為漫畫的ID，CHAPTER_ID為章節的ID。可指定多個CHAPTER_ID
'''

    pool = None

    @abstractmethod
    def name(self):
        """Website name of extractor, for filename of session file"""
        return ''

    def __init__(self):
        """Create extractor class, read session file"""

        # Override this with ProcessPoolExecutor for multiprocessing
        self.Executor = ThreadPoolExecutor
        self.is_interrupted = False

        # 讀取登錄信息
        # Use 0 instead of empty string to avoid LocalProtocolError
        self.token = '0'
        try:
            session_file = Path(__file__).parent / (self.name + '-session')
            with open(session_file, 'r') as f:
                self.token = f.read().rstrip()
        except:
            pass

        # 讀取設定
        self.config = {
            'threads': 4,
            'retries': 20
        }
        try:
            if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
                # In PyInstaller bundle
                config_filename = Path(sys.executable).parent / f'{self.name}-config.txt'
            else:
                config_filename = Path(__file__).parent / f'{self.name}-config.txt'
            if config_filename.exists():
                with config_filename.open('r', encoding='utf-8') as config_file:
                    lines = config_file.read().split('\n')
                for line in lines:
                    option = line.split()
                    if len(option) == 0:
                        continue
                    if option[0] == 'threads':
                        self.config['threads'] = int(option[1])
                    elif option[0] == 'retries':
                        self.config['retries'] = int(option[1])
        except Exception:
            print(traceback.format_exc())

    def main(self):
        signal.signal(signal.SIGINT, self.interrupt)
        self.arg_parse()

    def interrupt(self, sig, frame):
        if not multiprocessing.parent_process():
            print('收到中斷訊號，將結束程式')
        self.is_interrupted = True

    @abstractmethod
    def show_help(self):
        """Show help text, should probably output
        help_text or help_text_with_removed and format()"""
        pass

    def str_to_index(self, string, length):
        """Convert user input string to index of chapter list

        :param string: user input string
        :type string: str
        :param length: length of chapter list
        :type length: int
        :return: List of index
        :rtype: list[int]
        """
        def str_to_int(s, length):
            if s[0] == 'r':
                return length - int(s[1:])
            else:
                return int(s) - 1

        if '-' in string:
            start, end = [str_to_int(i, length) for i in string.split('-')]
            if start > end:
                return range(start, end - 1, -1)
            else:
                return range(start, end + 1)
        else:
            return [str_to_int(string, length)]

    def get_location(self):
        """Parse sys.argv and determine download location

        :return: Location for download file
        :rtype: str
        """
        try:
            pos = sys.argv.index('-o')
            location = sys.argv[pos + 1]
            del sys.argv[pos:pos + 2]
            return location
        except ValueError:
            return ''
        except IndexError:
            self.show_help()
            sys.exit(0)

    def arg_parse(self):
        """Parse sys.argv and do action"""
        if len(sys.argv) < 2:
            self.show_help()
            sys.exit(0)
        elif sys.argv[1] == 'login':
            if len(sys.argv) < 3:
                self.show_help()
                sys.exit(0)
            self.login(sys.argv[2:])
        elif sys.argv[1] == 'list-comic':
            if len(sys.argv) != 2:
                self.show_help()
                sys.exit(0)
            self.showBoughtComicList()
        elif sys.argv[1] == 'dl':
            location = self.get_location()
            if len(sys.argv) < 3:
                self.show_help()
                sys.exit(0)
            for comic_id in sys.argv[2:]:
                if self.is_interrupted:
                    return
                try:
                    self.downloadComic(comic_id, location)
                except Exception as e:
                    print(traceback.format_exc())
                    print(f'章節 {comic_id} 下載失敗：{e}')
        else:
            self.show_help()

    def decrypt_image(self, encrypted, idx, image_url, decrypt_info):
        """Override this if downloaded images need to be decrypted

        :param encrypted: encrypted image content
        :type encrypted: bytes
        :param idx: index (page number) of image, starts from 1
        :type idx: int
        :param image_url: url of image
        :type image_url: str
        :param decrypt_info: Information for image decryption
        :return: decrypted image
        :rtype: bytes
        """
        return encrypted

    def get_request(self, url, headers=None, cookies=None):
        """Wrapper of httpx.get() to retry failed request"""
        for i in range(self.config['retries']):
            if self.is_interrupted:
                raise Exception('被中斷')
            try:
                return httpx.get(url, headers=headers, cookies=cookies)
            except Exception as e:
                if i == self.config['retries'] - 1:
                    raise e

    def post_request(self, url, data=None, json=None, headers=None, cookies=None):
        """Wrapper of httpx.post() to retry failed request"""
        for i in range(self.config['retries']):
            if self.is_interrupted:
                raise Exception('被中斷')
            try:
                return httpx.post(url, data=data, json=json, headers=headers, cookies=cookies)
            except Exception as e:
                if i == self.config['retries'] - 1:
                    raise e

    def download_img(self, idx, image, headers, cookies, path, decrypt_info):
        """Called by download_worker to download image

        :param idx: index (page number) of image, starts from 1
        :type idx: int
        :param image: url of image
        :type image: str
        :param headers: headers used for image download
        :type headers: dict
        :param cookies: cookies used for image download
        :type cookies: dict
        :param path: Download location
        :type path: Path
        :param decrypt_info: Information for image decryption
        """
        try:
            if self.is_interrupted:
                return
            if self.image_extension:
                ext = self.image_extension
            else:
                image_name = urllib.parse.urlparse(image).path
                ext = Path(image_name).suffix
                # Fix Kuaikan and Kakao extension
                if ext == '.h' or ext == '.cef':
                    ext = Path(Path(image_name).stem).suffix
                if not ext:
                    ext = '.jpg'
            filename = Path(path, str(idx).zfill(3) + ext)
            if filename.exists():
                return

            r = self.get_request(image, headers=headers, cookies=cookies)
            content = self.decrypt_image(r.content, idx, image, decrypt_info)
            with filename.open('wb') as f:
                f.write(content)
        except Exception as e:
            print(traceback.format_exc())
            print(path / str(idx).zfill(3), '下載失敗：', e)

    def download_list(self, image_download):
        """Download images

        :param image_download: ImageDownload object
        :type image_download: ImageDownload
        """
        if self.is_interrupted:
            return
        root = image_download.root
        comic_title = self.fix_filename(image_download.comic_title)
        if image_download.chapter_title:
            chapter_title = self.fix_filename(image_download.chapter_title)
            print(f'下載{comic_title}/{chapter_title}')
            path = Path(root, comic_title, chapter_title)
        else:
            print(f'下載{comic_title}')
            path = Path(root, comic_title)
        path.mkdir(parents=True, exist_ok=True)
        if not ExtractorBase.pool:
            ExtractorBase.pool = self.Executor(max_workers=self.config['threads'])
        futures = [ExtractorBase.pool.submit(self.download_img, idx + 1, url, image_download.headers, image_download.cookies, path, image_download.decrypt_info) for idx, url in enumerate(image_download.urls)]
        wait(futures)

    def fix_filename(self, name):
        """Convert invalid filename to valid name

        :param name: comic or chapter name, which may be invalid filename
        :type name: str
        :return: valid filename
        :rtype: str
        """
        return name.replace('<', '＜').replace('>', '＞').replace(':', '：') \
                   .replace('"', '＂').replace('/', '⧸').replace('\\', '⧹') \
                   .replace('|', '│').replace('?', '？').replace('*', '＊') \
                   .replace('\t', ' ').replace('\x08', ' ').rstrip(' .')

    def login(self, token):
        """Write login information (token) to local session file

        :param token: User input token
        :type token: list[str]
        """
        if len(token) == 0:
            self.show_help()
            sys.exit(0)
        session_file = Path(__file__).parent / (self.name + '-session')
        with open(session_file, 'w') as f:
            for i in token:
                f.write(i + '\n')

    @abstractmethod
    def downloadComic(self, comic_id, root):
        """Fetch image list of comic and download

        :param comic_id: id of comic
        :type comic_id: str
        :param root: root directory of download location
        :type root: str
        """
        pass

    def getBoughtComicList(self):
        """Fetch bought comic list from website

        :return: List of comic, which is (id, title)
        :rtype: list[tuple[str, str]]
        """
        self.show_help()
        sys.exit(0)

    def showBoughtComicList(self):
        """Display bought comic list"""
        for i in self.getBoughtComicList():
            print(i[0], i[1])

    def draw_image(self, src, dest, sx, sy, width, height, dx, dy):
        """Draw rectangular region of src image to dest image

        :param src: Source image
        :type src: PIL.Image.Image
        :param dest: Destination image
        :type dest: PIL.Image.Image
        :param sx: X coordinate of rectangle of source image
        :type sx: int
        :param sy: Y coordinate of rectangle of source image
        :type sy: int
        :param width: Width of rectangle
        :type width: int
        :param height: Width of rectangle
        :type height: int
        :param dx: X coordinate of rectangle of dest image
        :type dx: int
        :param dy: Y coordinate of rectangle of dest image
        :type dy: int
        """
        crop = src.crop((sx, sy, sx + width, sy + height))
        dest.paste(crop, (dx, dy))

    def getTitleIndexFromChapterList(self, comic_id, chapter_id):
        """Get title and index of chapter, by calling getChapterList()

        :param comic_id: id of comic
        :type comic_id: str
        :param chapter_id: id of chapter
        :type chapter_id: str
        :return: title and index of chapter
        :rtype: tuple[str, int]"""
        for index, chapter in enumerate(self.getChapterList(comic_id)):
            if chapter[0] == chapter_id:
                return chapter[1], index

class ExtractorBase(ExtractorNoChapterBase):
    help_text_basic = '''用法：
{0} {1}
{0} search QUERY
    搜索漫畫。QUERY為關鍵字
{0} list-chapter COMIC_ID
    列出漫畫章節。COMIC_ID為漫畫的ID
{0} dl [-o 下載位置] COMIC_ID CHAPTER_ID ...
    下載漫畫。COMIC_ID為漫畫的ID，CHAPTER_ID為章節的ID。可指定多個CHAPTER_ID
{0} dl-all [-o 下載位置] COMIC_ID ...
    下載漫畫所有章節。COMIC_ID為漫畫的ID。可指定多個COMIC_ID
{0} dl-seq [-o 下載位置] COMIC_ID ... INDEX
    依照章節序號下載漫畫。COMIC_ID為漫畫的ID，可指定多個COMIC_ID。INDEX為章節在list-chapter中的序號，序號前加r代表反序。也可使用-代表範圍。
'''
    help_text_with_bought = (help_text_basic +
'''{0} list-comic
    列出已購漫畫
{0} list-bought-chapter COMIC_ID
    列出已購漫畫章節。COMIC_ID為漫畫的ID
''')
    help_text_with_removed = (help_text_with_bought +
'''{0} dl-removed [-o 下載位置] COMIC_ID CHAPTER_ID ...
    下載下架漫畫。COMIC_ID為漫畫的ID，CHAPTER_ID為章節的ID。可指定多個CHAPTER_ID
{0} dl-all-removed [-o 下載位置] COMIC_ID ...
    下載下架漫畫所有章節。COMIC_ID為漫畫的ID。可指定多個COMIC_ID
{0} dl-seq-removed [-o 下載位置] COMIC_ID ... INDEX
    依照章節序號下載下架漫畫。COMIC_ID為漫畫的ID，可指定多個COMIC_ID。INDEX為章節在list-bought-chapter中的序號，序號前加r代表反序。也可使用-代表範圍。
''')

    def arg_parse(self):
        """Parse sys.argv and do action"""
        if len(sys.argv) < 2:
            self.show_help()
            sys.exit(0)
        elif sys.argv[1] == 'login':
            if len(sys.argv) < 3:
                self.show_help()
                sys.exit(0)
            self.login(sys.argv[2:])
        elif sys.argv[1] == 'list-comic':
            if len(sys.argv) != 2:
                self.show_help()
                sys.exit(0)
            self.showBoughtComicList()
        elif sys.argv[1] == 'search':
            if len(sys.argv) < 3:
                self.show_help()
                sys.exit(0)
            self.showSearchComicList(sys.argv[2])
        elif sys.argv[1] == 'list-chapter':
            if len(sys.argv) != 3:
                self.show_help()
                sys.exit(0)
            self.showChapterList(sys.argv[2])
        elif sys.argv[1] == 'list-bought-chapter':
            if len(sys.argv) != 3:
                self.show_help()
                sys.exit(0)
            self.showBoughtChapterList(sys.argv[2])
        elif sys.argv[1] == 'dl':
            location = self.get_location()
            if len(sys.argv) < 4:
                self.show_help()
                sys.exit(0)
            for chapter_id in sys.argv[3:]:
                if self.is_interrupted:
                    return
                try:
                    self.downloadChapter(sys.argv[2], chapter_id, location)
                except Exception as e:
                    print(traceback.format_exc())
                    print(f'章節 {chapter_id} 下載失敗：{e}')
        elif sys.argv[1] == 'dl-seq' or sys.argv[1] == 'dl-all':
            if sys.argv[1] == 'dl-all':
                sys.argv.append("1-r1")
            location = self.get_location()
            if len(sys.argv) < 4:
                self.show_help()
                sys.exit(0)
            for comic in sys.argv[2:-1]:
                if self.is_interrupted:
                    return
                try:
                    chapter_list = self.getChapterList(comic)
                except Exception as e:
                    print(f'漫畫 {comic} 無法獲得章節清單：{e}')
                    continue

                for index in self.str_to_index(sys.argv[-1], len(list(chapter_list))):
                    try:
                        chapter_id = str(chapter_list[index][0])
                    except IndexError:
                        print(f'錯誤：沒有第{index + 1}章')
                        continue
                    if self.is_interrupted:
                        return
                    try:
                        self.downloadChapter(comic, chapter_id, location)
                    except Exception as e:
                        print(traceback.format_exc())
                        print(f'章節 {chapter_id} 下載失敗：{e}')
        elif sys.argv[1] == 'dl-removed':
            location = self.get_location()
            if len(sys.argv) < 4:
                self.show_help()
                sys.exit(0)
            for chapter_id in sys.argv[3:]:
                if self.is_interrupted:
                    return
                try:
                    self.downloadRemovedChapter(sys.argv[2], chapter_id, location)
                except Exception as e:
                    print(f'章節 {chapter_id} 下載失敗：{e}')
        elif sys.argv[1] == 'dl-seq-removed' or sys.argv[1] == 'dl-all-removed':
            if sys.argv[1] == 'dl-all-removed':
                sys.argv.append("1-r1")
            location = self.get_location()
            if len(sys.argv) < 4:
                self.show_help()
                sys.exit(0)
            for comic in sys.argv[2:-1]:
                if self.is_interrupted:
                    return
                try:
                    chapter_list = self.getBoughtChapterList(comic)
                except Exception as e:
                    print(f'漫畫 {comic} 無法獲得章節清單：{e}')
                    continue
                for index in self.str_to_index(sys.argv[-1], len(list(chapter_list))):
                    try:
                        chapter_id = str(chapter_list[index][0])
                    except IndexError:
                        print(f'錯誤：沒有第{index + 1}章')
                        continue
                    if self.is_interrupted:
                        return
                    try:
                        self.downloadRemovedChapter(comic, chapter_id, location)
                    except Exception as e:
                        print(f'章節 {chapter_id} 下載失敗：{e}')
        else:
            self.show_help()

    @abstractmethod
    def getChapterList(self, comic_id):
        """Fetch chapter list from website

        :param comic_id: id of comic
        :type comic_id: str
        :return: List of chapter, which is (id, title, locked_status)
        :rtype: list[tuple[str, str, LockedStatus]]
        """
        pass

    def showChapterList(self, comic_id):
        """Display chapter list

        :param comic_id: id of comic
        :type comic_id: str
        """
        for index, i in enumerate(self.getChapterList(comic_id)):
            if i[2] == LockedStatus.locked:
                print('(鎖)', index + 1, i[1])
            else:
                print(index + 1, i[1])

    @abstractmethod
    def downloadChapter(self, comic_id, chapter_id, root):
        """Fetch image list of chapter and download

        :param comic_id: id of comic
        :type comic_id: str
        :param chapter_id: id of chapter
        :type chapter_id: str
        :param root: root directory of download location
        :type root: str
        """
        pass

    def getBoughtChapterList(self, comic_id):
        """Fetch bought chapter list from website

        :param comic_id: id of comic
        :type comic_id: str
        :return: List of chapter, which is (id, title)
        :rtype: list[tuple[str, str]]
        """
        chapters = self.getChapterList(comic_id)
        ret = []
        for chapter in chapters:
            if chapter[2] == LockedStatus.unlocked:
                ret.append(chapter)
        return ret

    def showBoughtChapterList(self, comic_id):
        """Display bought chapter list

        :param comic_id: id of comic
        :type comic_id: str
        """
        for index, i in enumerate(self.getBoughtChapterList(comic_id)):
            print(index + 1, i[1])

    def downloadRemovedChapter(self, comic_id, chapter_id, root):
        """Fetch image list of chapter of removed comic and download

        :param comic_id: id of comic
        :type comic_id: str
        :param chapter_id: id of chapter
        :type chapter_id: str
        :param root: root directory of download location
        :type root: str
        """
        self.show_help()
        sys.exit(0)

    def searchComic(self, query):
        """Search comic with query

        :param query: search keyword
        :type query: str
        :return: List of comic, which is (id, title)
        :rtype: list[tuple[str, str]]
        """
        self.show_help()
        sys.exit(0)

    def showSearchComicList(self, query):
        """Display search result comic list

        :param query: search keyword
        :type query: str
        """
        for i in self.searchComic(query):
            print(i[0], i[1])

    def downloadComic(self, comic_id, root):
        """Not used"""
        raise Exception('Not used')

class ImageDownload:
    """Class to pass download information to download_list()

    :param urls: List of image url to download
    :type urls: list[str]
    :param headers: Headers used for image download
    :type headers: dict
    :param cookies: Cookies used for image download
    :type cookies: dict
    :param root: root directory of download location
    :type root: str
    :param comic_title: comic title
    :type comic_title: str
    :param chapter_title: chapter title
    :type chapter_title: str
    """

    def __init__(self, root, comic_title, chapter_title=None):
        """Create ImageDownload object

        :param root: root directory of download location
        :type root: str
        :param comic_title: comic title
        :type comic_title: str
        :param chapter_title: chapter title
        :type chapter_title: str
        """
        self.urls = []
        self.headers = {}
        self.cookies = {}
        self.root = root
        self.comic_title = comic_title
        self.chapter_title = chapter_title
        self.decrypt_info = None

class LockedStatus:
    locked = 0
    free = 1
    unlocked = 2
    temp_unlocked = 3
import base64
import hashlib
import random
import sys
import time
import urllib.parse

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad



class Extractor(ExtractorBase):
    name = 'podo'

    def __init__(self):
        super().__init__()
        try:
            self.atn, self.user_id = self.token.splitlines()
        except:
            pass

    def show_help(self):
        print(self.help_text_with_bought.format(sys.argv[0],
'''login ATN
    抓包取得標頭authorization: Bearer後面的字串'''))

    def login(self, token):
        if len(token) != 1:
            self.show_help()
            sys.exit(0)
        token.append(self.get_user_id(token[0]))
        super().login(token)

    def getChapterList(self, comic_id):
        headers = {
            'authorization': 'Bearer ' + self.atn
        }
        response = self.get_request(f'https://pd.tencentac.com/episode/v1/views/content-home/contents/{comic_id}/episodes?limit=10000&offset=0&sort=', headers=headers)
        j = response.json()
        if not 'data' in j:
            raise Exception(j['errors'])
        chapters = j['data']['episodes']
        ret = []
        for chapter in chapters:
            ret.append((chapter['id'], chapter['title'], chapter['readable']))
        return ret

    def downloadChapter(self, comic_id, chapter_id, root):
        timestamp = str(int(time.time() * 100))
        nonce = ''.join(random.choices('nonce', k=30))
        json_data = {
            "download": False,
            "id": chapter_id,
            "nonce": nonce,
            "timestamp": timestamp,
            "type": "AES_CBC_WEBP"
        }
        headers = {
            'authorization': 'Bearer ' + self.atn
        }
        response = self.post_request(f'https://pd.tencentac.com/episode/v1/views/viewer/episodes/{chapter_id}/media-resources', headers=headers, json=json_data)
        j = response.json()
        if not 'data' in j:
            if j['errors'][0]['errorType'] == 'NO_LICENSE':
                raise Exception('未解鎖')
            raise Exception(j['errors'])
        aid = j['data']['media']['aid']
        zid = j['data']['media']['zid']
        comic_title = j['data']['content']['title']
        chapter_title = j['data']['episode']['title']
        no = j['data']['episode']['no']
        key, iv = self.decrypt_key(nonce, self.user_id, chapter_id, timestamp, aid, zid)
        image_download = ImageDownload(root, comic_title, f'{str(no).zfill(3)} {chapter_title}')
        image_download.decrypt_info = (key, iv)
        for i in j['data']['media']['files']:
            image_download.urls.append(i['url'])
        self.download_list(image_download)

    def getBoughtComicList(self):
        headers = {
            'authorization': 'Bearer ' + self.atn
        }
        response = self.get_request('https://pd.tencentac.com/history/v1/episode-purchased-summaries?limit=10000&offset=0', headers=headers)
        j = response.json()
        if not 'data' in j:
            raise Exception(j['errors'])
        ret = []
        for comic in j['data']['episodePurchasedSummaries']:
            ret.append((comic['content']['id'], comic['content']['title'], False))
        return ret

    def getBoughtChapterList(self, comic_id):
        headers = {
            'authorization': 'Bearer ' + self.atn
        }
        response = self.get_request('https://pd.tencentac.com/history/v1/episode-purchased?limit=10000&offset=0&contentId=' + comic_id, headers=headers)
        j = response.json()
        if not 'data' in j:
            raise Exception(j['errors'])
        chapters = j['data']['episodePurchased']
        ret = []
        for chapter in chapters:
            ret.append((chapter['episode']['id'], chapter['episode']['title']))
        return ret

    def searchComic(self, query):
        response = self.get_request('https://pd.tencentac.com/search/v2/content?offset=0&limit=30&word=' + urllib.parse.quote_plus(query))
        j = response.json()
        if not 'data' in j:
            raise Exception(j['errors'])
        ret = []
        for i in j['data']['content']:
            ret.append((i['id'], i['title']))
        return ret

    def get_user_id(self, atn):
        response = self.get_request('https://pd.tencentac.com/auth/v1/auth/user/detail?access_token=' + atn)
        j = response.json()
        if not 'data' in j:
            raise Exception(j['errors'])
        return j['data']['userId']

    def decrypt_key(self, nonce, userId, chapterId, timestamp, aid, zid):
        aid = base64.b64decode(aid)
        zid = base64.b64decode(zid)
        key = (userId + chapterId + timestamp).encode()
        key = hashlib.sha256(key).digest()
        iv = (nonce + timestamp).encode()
        iv = hashlib.sha256(iv).digest()[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        key_return = unpad(cipher.decrypt(aid), 16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        iv_return = unpad(cipher.decrypt(zid), 16)
        return key_return, iv_return

    def decrypt_image(self, encrypted, idx, image_url, decrypt_info):
        key, iv = decrypt_info
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(encrypted), 16)

if __name__ == '__main__':
    Extractor().main()
