import discord
from discord.ext import commands

client = commands.Bot(comman_prefix = '.')

@client.event
async def on_ready():
    print('Bot is ready.')

@client.event
async def on_member_join(member):
    print(f'(member) has joined a server.')

@client.event
async def on_member_remove(member):
    print(f'(member) has left a server.')

client.run(BOT_TOKEN)
