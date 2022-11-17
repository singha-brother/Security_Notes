
import asyncio
import time 
import aiohttp
from aiohttp.client import ClientSession

async def download_link(url:str,session:ClientSession):
    async with session.get(url) as response:
        result = await response.text()
        print(f'Read {len(result)} from {url}')

async def download_all(urls:list):
    my_conn = aiohttp.TCPConnector(limit=10)
    async with aiohttp.ClientSession(connector=my_conn) as session:
        tasks = []
        for url in urls:
            task = asyncio.ensure_future(download_link(url=url,session=session))
            tasks.append(task)
        await asyncio.gather(*tasks,return_exceptions=True) # the await must be nest inside of the session

url_list = ["https://pokeapi.co/api/v2/ability/" + str(i) for i in range(1, 101)]
# print(url_list)
start = time.time()
asyncio.run(download_all(url_list))
end = time.time()
print(f'download {len(url_list)} links in {end - start} seconds')