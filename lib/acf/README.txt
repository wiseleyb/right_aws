Below is some code to get you started with Private Cloudfront Distributions.  This library is currently in production
on http://deucescracked.com but it's still kind of rough and I haven't done tests for it.  We had a hell of time
figuring a lot of this stuff out so, hopefully this helps someone.  Feel free to contact me with questions and/or
requests:  wiseleyb at gmail dot com

Examples:
-----------------------------------------------------------------------------------

  @amz_public_key       # S3 Public key
  @amz_private_key       # S3 Private key

  You need to create a key/pair to do much of anything with aws.  You can do this by going to
  http://aws-portal.amazon.com/gp/aws/developer/account/index.html?action=access-key and clicking
  on the Key Pairs tab

  @key_id               # Key ID from AWS (not the EC2 key/pairs)
  @pem_file             # Location of pem file associated with @key_id

  @private_bucket      # If you're using a public bucket things are simpler

  @acf = RightAws::AcfInterface.new(@amz_public_key, @amz_private_key)
  @s3 = RightAws::S3Interface.new(@amz_public_key, @amz_private_key)

====================================================================================
== Create a Private Streaming Distribution with access rights to a private bucket ==
====================================================================================


  # origin access identities are tied to distributions.  You need to grant them
  # rights to the bucket - which we'll show you how to do
  @s3_streaming_con_user_id   # we'll get this after creating a distro

  def create_private_streaming_distribution(bucket = @private_bucket)
    # see doc in create_distribution_by_config for explanation of enhanced_seek
    # we'll have this auto generate a origin access identity
    config = {:origin => "#{bucket}.s3.amazonaws.com", :comment => "Private Streaming Distro Test",
                         :streaming => true,
                         :enhanced_seek => true,
                         :enhanced_seek_zone => "server",
                         :auto_generate_origin_access_identity => true,
                         :trusted_signers => { :self => true }}
    res = @acf.create_distribution_by_config(config)
    oid = acf.get_origin_access_identity(res[:origin_access_identity])
    @s3_streaming_con_user_id = oid[:s3_canonical_user_id]

    #grant permissions for your distribution to the S3 bucket
    grant_permissions(@s3_streaming_con_user_id, "Full permissions for #{res[:aws_id]} ")

    return res[:aws_id]    # you'll need this to change the config of the distribution - you can also look this up on Amazon's Distribution console
  end

  def grant_permissions(bucket = @private_bucket, s3_con_user_id = @s3_streaming_con_user_id)
    res = @s3.add_s3canonical_grantee_to_bucket_and_objects(bucket, s3_con_user_id, "FULL_CONTROL", "Perms for #{@s3_con_id}")
    puts res.to_yaml
  end

  # You can now get expiring urls for your private streaming distribution.  Depending on the player you're using you might
  # might need to do something different.  For deucescracked.com we have a custom player, I also tested this on JW Player.
  # See method get_private_streaming_file for more options
  # Example:

  # JW Player
  url = RightAws::AcfInterface::AcfDistribution.get_private_streaming_url_for_jw_player(
                                  :distribution => 'asdfasdfasdf.cloudfront.net', #streaming distro url or cname associated with it
                                  :resource => 'some valid s3 key in your bucket',
                                  :key_pair_id => @key_id,
                                  :key_pair_pem_file_name => @pem_file,
                                  :expires => Time.now + 30.minutes)
  <embed
    src='http://github.s3.amazonaws.com/downloads%2Fwiseleyb%2Fright_aws%2Fplayer2.swf'
    width='470'
    height='290'
    bgcolor='#ffffff'
    allowscriptaccess='always'
    allowfullscreen='true'
    flashvars='<%url%>'/>


====================================================================================
== Create a Private Distribution with access rights to a private bucket            ==
====================================================================================

This is very similar to streaming... only you can get download urls.


# origin access identities are tied to distributions.  You need to grant them
# rights to the bucket - which we'll show you how to do
@s3_con_user_id   # we'll get this after creating a distro

def create_private_distribution(bucket = @private_bucket)
  # we'll have this auto generate a origin access identity
  config = {:origin => "#{bucket}.s3.amazonaws.com", :comment => "Private Download Distro Test",
                       :streaming => false,
                       :auto_generate_origin_access_identity => true,
                       :trusted_signers => { :self => true }}
  res = @acf.create_distribution_by_config(config)
  oid = acf.get_origin_access_identity(res[:origin_access_identity])
  @s3_con_user_id = oid[:s3_canonical_user_id]

  #grant permissions for your distribution to the S3 bucket
  grant_permissions(@s3_con_user_id, "Full permissions for #{res[:aws_id]} ")

  return res[:aws_id]    # you'll need this to change the config of the distribution - you can also look this up on Amazon's Distribution console
end

def grant_permissions(bucket = @private_bucket, s3_con_user_id = @s3_streaming_con_user_id)
  res = @s3.add_s3canonical_grantee_to_bucket_and_objects(bucket, s3_con_user_id, "FULL_CONTROL", "Perms for #{@s3_con_id}")
  puts res.to_yaml
end

Now - generate a download url

RightAws::AcfInterface::AcfDistribution.get_private_download_url(
                          :distribution => "asdfasdf.cloudfront.net", #download distro url or cname associated with it
                          :resource => 'some valid s3 key in your bucket',
                          :key_pair_id => @key_id,
                          :key_pair_pem_file_name => @pem_file,
                          :expires => Time.now + 30.minutes)


================================================================================
For more information don't hesitate to email me at wiseleyb at gmail com

