# import asyncio
# from typing import List
# from motor.motor_asyncio import AsyncIOMotorClient
# from config import config
# from dataclasses import dataclass, fields
# from api.builders.cve_builder import CveTupleBuilder, Cve

# import logging as log

# uri = f"mongodb://localhost:27017"

# async def insert_values(cve):

#     try: 
#         client = AsyncIOMotorClient(uri)
#         db = client.cves
#         cve_collection = db.cves

#         result = await cve_collection.insert_one(cve)

#         log.debug(f"[insert_values] Inserted {cve}")

#     except Exception as e:
#         log.warning(f"[insert_values] {e}")


# async def check_cve(cve_id: str) -> bool:
#     try:
#         client = AsyncIOMotorClient(uri)
#         db = client.cves
#         cve_collection = db.cves

#         result = await cve_collection.find({'id': cve_id} ).to_list(None)

#         log.debug(f"[insert_values] Find cve with id {cve_id}")

#     except Exception as e:
#         log.warning(f"[insert_values] {e}")

#     if result: 
#         return True
    
#     return False

# @dataclass
# class test_dataclass():
#     id: str

#     @classmethod
#     def test():
#         for i in 



# asyncio.run(check_cve("CVE-2017-2131"))