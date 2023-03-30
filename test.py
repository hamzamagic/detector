from virusshare import VirusShare

v = VirusShare('24610375250fa23e5dd6c6d72cc4b405c7f6384cd3cf89be0960a94929b3099e')
a = v.info('75a2d61962f981834738df1e9b0a96f0')

print(a['data'])