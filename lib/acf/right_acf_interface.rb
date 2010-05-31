#
# Copyright (c) 2008 RightScale Inc
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

module RightAws

  # = RightAws::AcfInterface -- RightScale Amazon's CloudFront interface
  # The AcfInterface class provides a complete interface to Amazon's
  # CloudFront service.
  #
  # For explanations of the semantics of each call, please refer to
  # Amazon's documentation at
  # http://developer.amazonwebservices.com/connect/kbcategory.jspa?categoryID=211
  #
  # Example:
  #
  #  acf = RightAws::AcfInterface.new('1E3GDYEOGFJPIT7XXXXXX','hgTHt68JY07JKUY08ftHYtERkjgtfERn57XXXXXX')
  #
  #  list = acf.list_distributions #=>
  #    [{:status             => "Deployed",
  #      :domain_name        => "d74zzrxmpmygb.6hops.net",
  #      :aws_id             => "E4U91HCJHGXVC",
  #      :origin             => "my-bucket.s3.amazonaws.com",
  #      :cnames             => ["x1.my-awesome-site.net", "x1.my-awesome-site.net"]
  #      :comment            => "My comments",
  #      :last_modified_time => Wed Sep 10 17:00:04 UTC 2008 }, ..., {...} ]
  #
  #  distibution = list.first
  #
  #  info = acf.get_distribution(distibution[:aws_id]) #=>
  #    {:enabled            => true,
  #     :caller_reference   => "200809102100536497863003",
  #     :e_tag              => "E39OHHU1ON65SI",
  #     :status             => "Deployed",
  #     :domain_name        => "d3dxv71tbbt6cd.6hops.net",
  #     :cnames             => ["web1.my-awesome-site.net", "web2.my-awesome-site.net"]
  #     :aws_id             => "E2REJM3VUN5RSI",
  #     :comment            => "Woo-Hoo!",
  #     :origin             => "my-bucket.s3.amazonaws.com",
  #     :last_modified_time => Wed Sep 10 17:00:54 UTC 2008 }
  #
  #  config = acf.get_distribution_config(distibution[:aws_id]) #=>
  #    {:enabled          => true,
  #     :caller_reference => "200809102100536497863003",
  #     :e_tag            => "E39OHHU1ON65SI",
  #     :cnames           => ["web1.my-awesome-site.net", "web2.my-awesome-site.net"]
  #     :comment          => "Woo-Hoo!",
  #     :origin           => "my-bucket.s3.amazonaws.com"}
  #
  #  config[:comment] = 'Olah-lah!'
  #  config[:enabled] = false
  #  config[:cnames] << "web3.my-awesome-site.net"
  #
  #  acf.set_distribution_config(distibution[:aws_id], config) #=> true
  #
  class AcfInterface < RightAwsBase

    include RightAwsBaseInterface

    API_VERSION      = "2010-05-01"  #"2009-04-02"
    DEFAULT_HOST     = 'cloudfront.amazonaws.com'
    DEFAULT_PORT     = 443
    DEFAULT_PROTOCOL = 'https'
    DEFAULT_PATH     = '/'

    @@bench = AwsBenchmarkingBlock.new
    def self.bench_xml
      @@bench.xml
    end
    def self.bench_service
      @@bench.service
    end

    # Create a new handle to a CloudFront account. All handles share the same per process or per thread
    # HTTP connection to CloudFront. Each handle is for a specific account. The params have the
    # following options:
    # * <tt>:endpoint_url</tt> a fully qualified url to Amazon API endpoint (this overwrites: :server, :port, :service, :protocol). Example: 'https://cloudfront.amazonaws.com'
    # * <tt>:server</tt>: CloudFront service host, default: DEFAULT_HOST
    # * <tt>:port</tt>: CloudFront service port, default: DEFAULT_PORT
    # * <tt>:protocol</tt>: 'http' or 'https', default: DEFAULT_PROTOCOL
    # * <tt>:multi_thread</tt>: true=HTTP connection per thread, false=per process
    # * <tt>:logger</tt>: for log messages, default: RAILS_DEFAULT_LOGGER else STDOUT
    #
    #  acf = RightAws::AcfInterface.new('1E3GDYEOGFJPIT7XXXXXX','hgTHt68JY07JKUY08ftHYtERkjgtfERn57XXXXXX',
    #    {:logger => Logger.new('/tmp/x.log')}) #=>  #<RightAws::AcfInterface::0xb7b3c30c>
    #
    def initialize(aws_access_key_id=nil, aws_secret_access_key=nil, params={})
      init({ :name                => 'ACF',
             :default_host        => ENV['ACF_URL'] ? URI.parse(ENV['ACF_URL']).host   : DEFAULT_HOST,
             :default_port        => ENV['ACF_URL'] ? URI.parse(ENV['ACF_URL']).port   : DEFAULT_PORT,
             :default_service     => ENV['ACF_URL'] ? URI.parse(ENV['ACF_URL']).path   : DEFAULT_PATH,
             :default_protocol    => ENV['ACF_URL'] ? URI.parse(ENV['ACF_URL']).scheme : DEFAULT_PROTOCOL,
             :default_api_version => ENV['ACF_API_VERSION'] || API_VERSION },
           aws_access_key_id     || ENV['AWS_ACCESS_KEY_ID'],
           aws_secret_access_key || ENV['AWS_SECRET_ACCESS_KEY'],
           params)
    end

    #-----------------------------------------------------------------
    #      Requests
    #-----------------------------------------------------------------

    # Generates request hash for REST API.
    def generate_request(method, path, params={}, body=nil, headers={})  # :nodoc:
      # Params
      params.delete_if{ |key, val| val.blank? }
      unless params.blank?
        path += "?" + params.to_a.collect{ |key,val| "#{AwsUtils::amz_escape(key)}=#{AwsUtils::amz_escape(val.to_s)}" }.join("&")
      end
      # Headers
      headers['content-type'] ||= 'text/xml' if body
      headers['date'] = Time.now.httpdate
      # Auth
      signature = AwsUtils::sign(@aws_secret_access_key, headers['date'])
      headers['Authorization'] = "AWS #{@aws_access_key_id}:#{signature}"
      # Request
      path    = "#{@params[:service]}#{@params[:api_version]}/#{path}"
      request = "Net::HTTP::#{method.capitalize}".constantize.new(path)
      request.body = body if body
      # Set request headers
      headers.each { |key, value| request[key.to_s] = value }
      # prepare output hash
      { :request  => request,
        :server   => @params[:server],
        :port     => @params[:port],
        :protocol => @params[:protocol] }
      end

      # Sends request to Amazon and parses the response.
      # Raises AwsError if any banana happened.
    def request_info(request, parser, &block) # :nodoc:
      request_info_impl(:acf_connection, @@bench, request, parser, &block)
    end

    #-----------------------------------------------------------------
    #      Helpers:
    #-----------------------------------------------------------------

    def self.escape(text) # :nodoc:
      REXML::Text::normalize(text)
    end

    def self.unescape(text) # :nodoc:
      REXML::Text::unnormalize(text)
    end

    def generate_call_reference # :nodoc:
      result = Time.now.strftime('%Y%m%d%H%M%S')
      10.times{ result << rand(10).to_s }
      result
    end

    def merge_headers(hash) # :nodoc:
      hash[:location] = @last_response['Location'] if @last_response['Location']
      hash[:e_tag]    = @last_response['ETag']     if @last_response['ETag']
      hash
    end

    # see docs for create_distribution_by_config below
    # TODO - this needs better doc
    def config_to_xml(config) # :nodoc:
      #config.requires!(:origin)
      origin = config[:origin]
      unless origin.include?(".") #try to fix it for them
        origin = "#{origin}.s3.amazonaws.com"
      end

      comment = config[:comment] || ''

      enabled = config[:enabled] || true

      #reference
      caller_reference = generate_call_reference || config[:caller_reference]

      #cnames
      cnames_str = ''
      unless config[:cnames].blank?
        config[:cnames].to_a.each { |cname| cnames_str += "\n  <CNAME>#{cname}</CNAME>" }
      end

      # logging
      logging = ""
      if config[:logging] && config[:logging][:bucket]
        logging =  "\n           <Logging>"
        logging << "\n             <Bucket>#{config[:logging][:bucket]}</Bucket>"
        logging << "\n             <Prefix>#{config[:logging][:prefix]}</Prefix>" if config[:logging][:prefix]
        logging << "\n           </Logging>"
      end

      # origin access identity
      origin_access_identity = config[:origin_access_identity] || ""
      unless origin_access_identity.blank?
        unless origin_access_identity.starts_with?("origin-access-identity/cloudfront/")
          origin_access_identity = "origin-access-identity/cloudfront/#{config[:origin_access_identity]}"
        end
        origin_access_identity = "\n           <OriginAccessIdentity>#{origin_access_identity}</OriginAccessIdentity>"
      end
      if config[:auto_generate_origin_access_identity] == true && origin_access_identity.blank?
        oac = create_origin_access_identity(:comment => "Identity for bucket #{config[:origin]}")
        origin_access_identity = "origin-access-identity/cloudfront/#{oac[:id]}"
        origin_access_identity = "\n           <OriginAccessIdentity>#{origin_access_identity}</OriginAccessIdentity>"
      end

      # trusted signers
      trusted_signers = ""
      if config[:trusted_signers]
        config[:trusted_signers][:self] ||= true
        config[:trusted_signers][:aws_account_numbers] ||= []
        trusted_signers =  "\n           <TrustedSigners>"
        trusted_signers << "\n             <Self/>" unless config[:trusted_signers][:self] == false
        if config[:trusted_signers][:aws_account_numbers].is_a?(Array)
          config[:trusted_signers][:aws_account_numbers].each do |aws_account_number|
            trusted_signers << "\n             <AwsAccountNumber>#{aws_account_number}</AwsAccountNumber>"
          end
        end
        trusted_signers << "\n           </TrustedSigners>"
      end

      config[:streaming] ||= false
      if config[:streaming] == true
        streaming = "Streaming"
        if config[:enhanced_seek] == true
          config[:enhanced_seek_zone] ||= "server"
          enhanced_seek = %(<EnhancedSeek zone="#{config[:enhanced_seek_zone]}">#{config[:enhanced_seek]}</EnhancedSeek>)
        end
      end


      xml = <<-EOXML
        <?xml version="1.0" encoding="UTF-8"?>
        <#{streaming}DistributionConfig xmlns="#{xmlns}">
          <Origin>#{origin}</Origin>
          <CallerReference>#{caller_reference}</CallerReference>
          #{cnames_str.lstrip}
          <Comment>#{AcfInterface::escape(comment.to_s)}</Comment>
          <Enabled>#{enabled}</Enabled>
          #{logging}
          #{origin_access_identity}
          #{trusted_signers}
          #{enhanced_seek}
        </#{streaming}DistributionConfig>
      EOXML
      return xml
    end

    def xmlns
      "http://#{@params[:server]}/doc/#{API_VERSION}/"
    end

    #-----------------------------------------------------------------
    #      API Calls:
    #-----------------------------------------------------------------

    # List all distributions.
    # Returns an array of distributions or RightAws::AwsError exception.
    #
    #  acf.list_distributions #=>
    #    [{:status             => "Deployed",
    #      :domain_name        => "d74zzrxmpmygb.6hops.net",
    #      :aws_id             => "E4U91HCJHGXVC",
    #      :cnames             => ["web1.my-awesome-site.net", "web2.my-awesome-site.net"]
    #      :origin             => "my-bucket.s3.amazonaws.com",
    #      :comment            => "My comments",
    #      :last_modified_time => Wed Sep 10 17:00:04 UTC 2008 }, ..., {...} ]
    #
    # params:
    # <tt>:max_items</tt>: max number of items to get
    # <tt>:marker</tt>: starting point (for something like paging)
    # <tt>:streaming</tt>: default false - getting streaming distributions and normal distributions are different calls
    # TODO - it'd be nice to have this return streaming and non-streaming in one call
    def list_distributions(params)
      params[:max_items] ||= 100
      result = []
      incrementally_list_distributions(params) do |response|
        result += response[:distributions]
        true
      end
      result
    end

    # List all streaming distributions.  See <tt>list_distributions</tt> for more info.
    # Returns an array of distributions or RightAws::AwsError exception.
    # params:
    # <tt>:max_items</tt>: max number of items to get
    # <tt>:marker</tt>: starting point (for something like paging)
    def list_streaming_distributions(params = {})
      params[:streaming] = true
      list_distributions(params)
    end

    # Incrementally list distributions.
    #
    # Optional params: +:marker+ and +:max_items+.
    #
    #   # get first distribution
    #   incrementally_list_distributions(:max_items => 1) #=>
    #      {:distributions=>
    #        [{:status=>"Deployed",
    #          :aws_id=>"E2Q0AOOMFNPSYL",
    #          :logging=>{},
    #          :origin=>"my-bucket.s3.amazonaws.com",
    #          :domain_name=>"d1s5gmdtmafnre.6hops.net",
    #          :comment=>"ONE LINE OF COMMENT",
    #          :last_modified_time=>Wed Oct 22 19:31:23 UTC 2008,
    #          :enabled=>true,
    #          :cnames=>[]}],
    #       :is_truncated=>true,
    #       :max_items=>1,
    #       :marker=>"",
    #       :next_marker=>"E2Q0AOOMFNPSYL"}
    #
    #   # get max 100 distributions (the list will be restricted by a default MaxItems value ==100 )
    #   incrementally_list_distributions
    #
    #   # list distributions by 10
    #   incrementally_list_distributions(:max_items => 10) do |response|
    #     puts response.inspect # a list of 10 distributions
    #     false # return false if the listing should be broken otherwise use true
    #   end
    #
    # params:
    # <tt>:max_items</tt>: max number of items to get
    # <tt>:marker</tt>: starting point (for something like paging)
    # <tt>:streaming</tt>: default false - getting streaming distributions and normal distributions are different calls
    def incrementally_list_distributions(params={}, &block)
      opts = {}
      opts['MaxItems'] = params[:max_items] if params[:max_items]
      opts['Marker']   = params[:marker]    if params[:marker]
      url = "distribution"
      url = "streaming-#{url}" if params[:streaming]
      last_response = nil
      loop do
        link = generate_request('GET', url, opts)
        last_response = request_info(link,  AcfDistributionListParser.new(:logger => @logger))
        opts['Marker'] = last_response[:next_marker]
        break unless block && block.call(last_response) && !last_response[:next_marker].blank?
      end
      last_response
    end

    # Incrementally list streaming distributions.  See <tt>incrementally_list_distributions</tt> for more info.
    # params:
    # <tt>:max_items</tt>: max number of items to get
    # <tt>:marker</tt>: starting point (for something like paging)
    def incrementally_list_streaming_distributions(params = {}, &block)
      params[:streaming] = true
      incrementally_list_distributions(params, &block)
    end

    # Create a new distribution.
    # Returns the just created distribution or RightAws::AwsError exception.
    #
    #  acf.create_distribution('my-bucket.s3.amazonaws.com', 'Woo-Hoo!', true, ['web1.my-awesome-site.net'],
    #                          { :prefix=>"log/", :bucket=>"my-logs.s3.amazonaws.com" } ) #=>
    #    {:comment            => "Woo-Hoo!",
    #     :enabled            => true,
    #     :location           => "https://cloudfront.amazonaws.com/2008-06-30/distribution/E2REJM3VUN5RSI",
    #     :status             => "InProgress",
    #     :aws_id             => "E2REJM3VUN5RSI",
    #     :domain_name        => "d3dxv71tbbt6cd.6hops.net",
    #     :origin             => "my-bucket.s3.amazonaws.com",
    #     :cnames             => ["web1.my-awesome-site.net"],
    #     :logging            => { :prefix => "log/",
    #                              :bucket => "my-logs.s3.amazonaws.com"},
    #     :last_modified_time => Wed Sep 10 17:00:54 UTC 2008,
    #     :caller_reference   => "200809102100536497863003"}
    #
    def create_distribution(origin, comment='', enabled=true, cnames=[], caller_reference=nil, logging={})
      config = { :origin  => origin,
                 :comment => comment,
                 :enabled => enabled,
                 :cnames  => cnames.to_a,
                 :caller_reference => caller_reference }
      config[:logging] = logging unless logging.blank?
      create_distribution_by_config(config)
    end

    # Create a new distribution with full support for 2010/03/01 features (private distributions)
    # See http://docs.amazonwebservices.com/AmazonCloudFront/latest/APIReference/index.html?DistributionConfigDatatype.html
    # config => {
    #   :origin             => "my-bucket.s3.amazonaws.com",              REQUIRED
    #   :caller_reference   => 123456789,                                 OPTIONAL - auto generated if missing
    #   :cnames             => ['one.mysite.com', 'two.mysite.com'],      OPTIONAL - limited to 10 items by aws
    #   :comment            => "blah blah",                               OPTIONAL
    #   :enabled            => true/false,                                defaults to true
    #   :logging            =>  {                                         OPTIONAL
    #           :bucket     => "my-log-bucket.s3.aazonaws.com",             required if :logging exists
    #           :prefix     => "log/"}                                      optional
    #   :origin_access_identity => "E74FTE3AJFJ256A",                     OPTIONAL if present distribution will be private
    #   :auto_generate_origin_access_identity => true/false,              OPTIONAL if true code will auto-generate origin access identity
    #   :trusted_signers    => {                                          OPTIONAL
    #           :self       => true/false,                                  optional - defaults to true
    #           :aws_account_numbers => []}                                 optional array of aws account numbers that can create signed urls
    #   :streaming          => true/false                                 OPTIONAL defaults to false - decides if distribution is a streaming distribution
=begin

Enhanced seeking... while not an expert in this... essentially, in videos you have key frames every X frames.  MP4
compression works (roughly) by removing bits that don't change from frame to frame.  A key frame is a new start
for this compression technique.  Without them you'd essentially need to start at the begging of the media stream
to figure out what to send.  Not good if you want to jump to hour 2 in a 3 hour video.  To decrease file size you
increase the number of frames per key frame.  The down side of this is that, when your users
try to jump a head in the video they can only jump to key frames.  Enhanced seeking uses some fancy algo to fix this.
This is completely undocumented (as of 5/7/2010) but Amazon sent us (ben) this:

            <!-- If there is no key frame at the point of seek server will perform ->
            <!- accurate seeking based on the nearest key and intermediate frames. ->
            <!- Default = true. The zone attribute can be set to "client", "server". ->
            <!- If zone is set to "client", no keyframe will be generated in the ->
            <!- the server, but all the information for accurate seeking will passed ->
            <!- and processed on the client side. ->
            <!- If zone is set to "server", a new keyframe will be created on the ->
            <!- server side based on the previous keyframe and intermediate frames. ->
            <!- If the zone attribute is missing, server will fall back to the old ->
            <!- behavior where enhanced seeking will be handled by the server for ->
            <!- Sorenson codec. For the other video codec, enhanced will be handled ->
            <!- by the client. -->
            <EnhancedSeek zone="client">true</EnhancedSeek>
=end
    #   :enhanced_seek      => true/false                                 OPTIONAL only for streaming=true - turns on Amazon's completely undocumented but very useful enhanced seek option
    #   :enhanced_seek_zone => client/server                              OPTIONAL only for streaming=true and enhanced_seek = true - defaults to server - decides where enhanced seek is performed
    # }
    # Example:  create private distribution
    # create_distribution_by_config(:origin => "my-bucket.s3.amazonaws.com", :comment => "private distribution",
    #                     :auto_gneerate_origin_access_identity => true,
    #                     :trusted_signers => { :self => true })
    #
    # Example:  create a private streaming distribution
    # config = {:origin => "#{bucket}.s3.amazonaws.com", :comment => "Enhanced Seek Test",
    #                      :streaming => true,
    #                      :enhanced_seek => true,
    #                      :enhanced_seek_zone => "server",
    #                      :auto_generate_origin_access_identity => true,
    #                      :trusted_signers => { :self => true }}
    # @acf.create_distribution_by_config(config)
    def create_distribution_by_config(config)
      config[:caller_reference] ||= generate_call_reference
      post_to = config[:streaming] == true ? "streaming-distribution" : "distribution"
      link = generate_request('POST', post_to, {}, config_to_xml(config))
      merge_headers(request_info(link, AcfDistributionListParser.new(:logger => @logger))[:distributions].first)
    end

    # Create a origin access identity (for use in creating private distributions)
    # create_origin_access_identity(:caller_reference => 12345132, :comment => "yippie!") =>
    #  {:id           => "E74FTE3AJFJ256A",
    #   :s3_canonical_user_id => "cd13868f797c227fbea2830611a26fe0a21ba1b826ab4bed9b7771c9a69ba19f",
    #   :cloud_front_origin_access_identity_config => {
    #     :caller_reference => "12345132",
    #     :comment => "yippie!"
    #    }
    #  }
    def create_origin_access_identity(options = {})
      # generate something like this
      # http://docs.amazonwebservices.com/AmazonCloudFront/latest/DeveloperGuide/index.html?PrivateContent.html
      # <?xml version="1.0" encoding="UTF-8"?>
      # <CloudFrontOriginAccessIdentityConfig xmlns="http://cloudfront.amazonaws.com/doc/2010-03-01/">
      #   <CallerReference>20091130090000</CallerReference>
      #   <Comment>Your comments here</Comment>
      # </CloudFrontOriginAccessIdentityConfig>

      # get back something like
      # <?xml version="1.0" encoding="UTF-8"?>
      # <CloudFrontOriginAccessIdentity xmlns="http://cloudfront.amazonaws.com/doc/2010-03-01/">
      #   <Id>E74FTE3AJFJ256A</Id>
      #   <S3CanonicalUserId>
      #      cd13868f797c227fbea2830611a26fe0a21ba1b826ab4bed9b7771c9a69ba19f
      #   </S3CanonicalUserId>
      #   <CloudFrontOriginAccessIdentityConfig>
      #     <CallerReference>20091130090000</CallerReference>
      #     <Comment>Your comments here</Comment>
      #   </CloudFrontOriginAccessIdentityConfig>
      # </CloudFrontOriginAccessIdentity>

      # reference
      caller_reference = nil || options[:caller_reference]
      caller_reference ||= generate_call_reference
      body = <<-EOXML
        <?xml version="1.0" encoding="UTF-8"?>
        <CloudFrontOriginAccessIdentityConfig xmlns="http://cloudfront.amazonaws.com/doc/2010-03-01/">
          <CallerReference>#{caller_reference}</CallerReference>
          <Comment>#{options[:comment]}</Comment>
        </CloudFrontOriginAccessIdentityConfig>
      EOXML
      link = generate_request('POST', 'origin-access-identity/cloudfront', {}, body)
      merge_headers(request_info(link, AcfOriginAccessIdentityParser.new(:logger => @logger)))
    end

    def get_origin_access_identity(aws_id)
      #try to make it idiot proof - origin-access-identy returns from distory is a partial url
      if aws_id.include?("/")
        aws_id = aws_id.split("/").last
      end
      url = "origin-access-identity"
      link = generate_request('GET', "#{url}/cloudfront/#{aws_id}")
      merge_headers(request_info(link, AcfOriginAccessIdentityParser.new(:logger => @logger)))
    end

    # options
    #    :marker      defaults to nil - for use when paging:  Use this when paginating results to indicate
                     # where to begin in your list of origin access identities. The results include identities
                     # in the list that occur after the marker. To get the next page of results, set the Marker
                     # to the value of the NextMarker from the current page's response (which is also the ID of
                     # the last identity on that page).
    #    :max_items   defaults to 100
    def list_origin_access_identities(options = {})
      options[:max_items] ||= 100
      url = "origin-access-identity"
      link = generate_request('GET', "#{url}/cloudfront?Marker=#{options[:marker]}&MaxItems=#{options[:max_items]}")
      merge_headers(request_info(link, AcfOriginAccessIdentityListParser.new(:logger => @logger)))
    end

    # TODO
    # def incrementally_list_origin_access_identities
    # def list_all_origin_access_identities
    # def set_origin_access_identity
    # def delete_origin_access_identity

    # Get a distribution's information.
    # Returns a distribution's information or RightAws::AwsError exception.
    #
    #  acf.get_distribution('E2REJM3VUN5RSI') #=>
    #    {:enabled            => true,
    #     :caller_reference   => "200809102100536497863003",
    #     :e_tag              => "E39OHHU1ON65SI",
    #     :status             => "Deployed",
    #     :domain_name        => "d3dxv71tbbt6cd.6hops.net",
    #     :cnames             => ["web1.my-awesome-site.net", "web2.my-awesome-site.net"]
    #     :aws_id             => "E2REJM3VUN5RSI",
    #     :comment            => "Woo-Hoo!",
    #     :origin             => "my-bucket.s3.amazonaws.com",
    #     :last_modified_time => Wed Sep 10 17:00:54 UTC 2008 }
    #
    # options -
    #   :streaming - t/f
    def get_distribution(aws_id, options = {})
      url = "distribution"
      url = "streaming-#{url}" if options[:streaming] == true
      link = generate_request('GET', "#{url}/#{aws_id}")
      merge_headers(request_info(link, AcfDistributionListParser.new(:logger => @logger))[:distributions].first)
    end
    def get_streaming_distribution(aws_id)
      get_distribution(aws_id, {:streaming => true})
    end

    # Get a distribution's configuration.
    # Returns a distribution's configuration or RightAws::AwsError exception.
    #
    #  acf.get_distribution_config('E2REJM3VUN5RSI') #=>
    #    {:enabled          => true,
    #     :caller_reference => "200809102100536497863003",
    #     :e_tag            => "E39OHHU1ON65SI",
    #     :cnames           => ["web1.my-awesome-site.net", "web2.my-awesome-site.net"]
    #     :comment          => "Woo-Hoo!",
    #     :origin           => "my-bucket.s3.amazonaws.com"}
    #
    # options -
    #   :streaming - t/f
    def get_distribution_config(aws_id, options = {})
      url = "distribution"
      url = "streaming-#{url}" if options[:streaming] == true
      link = generate_request('GET', "#{url}/#{aws_id}/config")
      merge_headers(request_info(link, AcfDistributionListParser.new(:logger => @logger))[:distributions].first)
    end
    def get_streaming_distribution_config(aws_id)
      get_distribution_config(aws_id, {:streaming => true})
    end

    # Set a distribution's configuration
    # (the :origin and the :caller_reference cannot be changed).
    # Returns +true+ on success or RightAws::AwsError exception.
    #
    #  config = acf.get_distribution_config('E2REJM3VUN5RSI') #=>
    #    {:enabled          => true,
    #     :caller_reference => "200809102100536497863003",
    #     :e_tag            => "E39OHHU1ON65SI",
    #     :cnames           => ["web1.my-awesome-site.net", "web2.my-awesome-site.net"]
    #     :comment          => "Woo-Hoo!",
    #     :origin           => "my-bucket.s3.amazonaws.com"}
    #  config[:comment] = 'Olah-lah!'
    #  config[:enabled] = false
    #  acf.set_distribution_config('E2REJM3VUN5RSI', config) #=> true
    #
    # options -
    #   :streaming - t/f
    def set_distribution_config(aws_id, config, options = {})
      url = "distribution"
      url = "streaming-#{url}" if options[:streaming] == true
      link = generate_request('PUT', "#{url}/#{aws_id}/config", {}, config_to_xml(config),
                                     'If-Match' => config[:e_tag])
      puts link.to_yaml
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end
    def set_streaming_distribution_config(aws_id, config)
      config[:streaming] = true
      set_distribution_config(aws_id, config, {:streaming => true})
    end

    # Delete a distribution. The enabled distribution cannot be deleted.
    # Returns +true+ on success or RightAws::AwsError exception.
    #
    #  acf.delete_distribution('E2REJM3VUN5RSI', 'E39OHHU1ON65SI') #=> true
    #
    # options -
    #   :streaming - t/f
    def delete_distribution(aws_id, e_tag, options = {})
      url = "distribution"
      url = "streaming-#{url}" if options[:streaming] == true
      link = generate_request('DELETE', "#{url}/#{aws_id}", {}, nil,
                                        'If-Match' => e_tag)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end
    def delete_streaming_distribution(aws_id, e_tag)
      delete_distribution(aws_id, e_tag, {:streaming => true})
    end

    #-----------------------------------------------------------------
    #      CLOUD DISTRIBUTION OBJECT:
    #-----------------------------------------------------------------
    class AcfDistribution

      # url of the distribution http://d3561sl5litxcx.cloudfront.net or some cname http://images.mywebsite.com
      def initialize(url)
        @url = url
        @url = "#{@url}/" unless @url.ends_with?("/")
      end

      # => distribution                   required (you can use cname if you want)
      # => resource                       required - aws key of resource to use
      # => key_pair_id                    required - from amazon's key creation util (not the EC2 one though)
      # => key_pair_pem_file_name         required - .pem file that goes with key_id
      # => expires                        defaults to 1 hour - you can supply a Time object or an int (seconds since epoch)
      # TODO - allow user to pass in params
      def self.get_private_download_url(options = {})
        [:distribution, :resource, :key_pair_id, :key_pair_pem_file_name].each do |k|
          options.requires!(k)
        end
        d = options[:distribution]
        expires = expires_to_i(options[:expires])
        d = "#{d}/" unless d.ends_with?("/")
        d = "http://#{d}" unless d.starts_with?("http://")
        r = options[:resource]
        r = r.reverse.chop!.reverse if r.starts_with?("/")
        r.gsub!(' ','%20')
        url = "#{d}#{r}"
        sig = signature_for_resource(url, options[:key_pair_id], options[:key_pair_pem_file_name], expires)
        p = params_for_resource(expires, sig, options[:key_pair_id])
        "#{url}?#{p}"
      end

      # creates an expiring streaming file string
      # options
      # => resource                       required - aws key of resource to use
      # => key_pair_id                         required - from amazon's key creation util (not the EC2 one though)
      # => key_pair_pem_file_name          required - .pem file that goes with key_id
      # => expires                        defaults to 1 hour - you can supply a Time object or an int (seconds since epoch)
      # => encode_params = false          if true this will encode params after ?
      # => distribution = nil             if !nil? this will add &streamer=#{@url}/cfx/st
      # => prepend_file_type = true       if the resource is vid.mp4 it will create mp4:vid.mp4
      def self.get_private_streaming_file(options = {})
        [:resource, :key_pair_id, :key_pair_pem_file_name].each do |k|
          options.requires!(k)
        end
        resource = options[:resource]
        resource = resource.reverse.chop!.reverse if resource.starts_with?("/")
        key_id = options[:key_id]
        expires = expires_to_i(options[:expires])
        res = ""
        sig = signature_for_resource(resource, options[:key_pair_id], options[:key_pair_pem_file_name], expires)
        options[:prepend_file_type] == true if options[:prepend_file_type].blank?
        res << "#{resource.split(".").last}:" if options[:prepend_file_type] == true
        res << "#{resource}?"
        p = params_for_resource(expires, sig, options[:key_pair_id])
        if options[:encode_params].to_s == "true"
          res << "#{url_encode(p)}"
        else
          res << p
        end
        return res
      end

      # creates a expiring signed url for an object in a private distribution
      # options
      # => :distibution   cloudfront domain name or cname alias
      # => :resource      my_video.mp4
      # => :key_pair_id        key_id from amazon's key creation utility (not the EC2 one though)
      # => :key_pair_pem_file_name :: private key file for key_id (.pem) from amazon's key creation utility (not the EC2 one though)
      # => :expires       OPTIONAL - defaults to 1 hour, either Epoch (Unix) or Time object
      def self.get_private_streaming_url_for_jw_player(options = {})
        [:distribution, :resource, :key_pair_id, :key_pair_pem_file_name].each do |k|
          options.requires!(k)
        end
        options[:prepend_file_type] = true
        options[:encode_params] = true
        "file=#{get_private_streaming_file(options)}&streamer=rtmp://#{options[:distribution]}/cfx/st"
      end

      def self.policy_for_resource(resource, expires = Time.now + 1.hour)
        %({"Statement":[{"Resource":"#{resource}","Condition":{"DateLessThan":{"AWS:EpochTime":#{expires.to_i}}}}]})
      end

      def self.params_for_resource(expires, signature, key_pair_id)
        "Expires=#{expires.to_i}&Signature=#{signature}&Key-Pair-Id=#{key_pair_id}"
      end

      def self.signature_for_resource(resource, key_id, private_key_file_name, expires = Time.now + 1.hour)
          policy = policy_for_resource(resource, expires)
          key = OpenSSL::PKey::RSA.new(File.readlines(private_key_file_name).join("").strip)
          url_safe(Base64.encode64(key.sign(OpenSSL::Digest::SHA1.new, (policy))))
      end

      def self.url_safe(str)
        str.gsub('+','-').gsub('=','_').gsub('/','~').gsub(/\n/,'').gsub(' ','')
      end

      def self.expires_to_i(e)
        expires = (Time.now + 1.hour).to_i
        if e.is_a?(Time)
          expires = e.to_i
        elsif e.to_i > 0
          expires = e.to_i
        end
        return expires
      end
    end

    #-----------------------------------------------------------------
    #      PARSERS:
    #-----------------------------------------------------------------

    class AcfOriginAccessIdentityParser < RightAWSParser # :nodoc:
      def reset
        @result = { :cloud_front_origin_access_identity_config => {} }
        @cfoaic = {}
      end
      def tagstart(name, attributes)
        case name
        when 'CloudFrontOriginAccessIdentityConfig' then   @cfoaic = {}
        end
      end
      def tagend(name)
        case name
          when 'Id'                   then @result[:id]                                     = @text
          when 'S3CanonicalUserId'    then @result[:s3_canonical_user_id]                   = @text
          when 'CloudFrontOriginAccessIdentityConfig'
                                      then @result[:cloud_front_origin_access_identity_config] = @cfoaic
          when 'CallerReference'      then @cfoaic[:caller_reference]                       = @text
          when 'Comment'              then @cfoaic[:comment]                                = AcfInterface::unescape(@text)
        end
      end
    end

    class AcfOriginAccessIdentityListParser < RightAWSParser # :nodoc:
      def reset
        @result = { :cloud_front_origin_access_identity_summaries => [] }
        @cfoaic = {}
      end
      def tagstart(name, attributes)
        case name
        when 'CloudFrontOriginAccessIdentitySummary' then   @cfoaic = {}
        end
      end
      def tagend(name)
        case name
          when 'Marker'               then @result[:marker]                                 = @text
          when 'NextMarker'           then @result[:next_marker]                            = @text
          when 'MaxItems'             then @result[:max_items]                              = @text
          when 'IsTruncated'          then @result[:is_truncated]                           = (@text == "true")
          when 'Id'                   then @cfoaic[:id]                                     = @text
          when 'S3CanonicalUserId'    then @cfoaic[:s3_canonical_user_id]                   = @text
          when 'CloudFrontOriginAccessIdentitySummary'
                                      then @result[:cloud_front_origin_access_identity_summaries] << @cfoaic
          when 'Comment'              then @cfoaic[:comment]                                = AcfInterface::unescape(@text)
        end
      end
    end

    class AcfDistributionListParser < RightAWSParser # :nodoc:
      DIST_ARR = %w(DistributionSummary StreamingDistributionSummary Distribution StreamingDistribution)
      DIST_CONFIG_ARR = %w(DistributionConfig StreamingDistributionConfig)
      def reset
        @result = { :distributions => [] }
      end
      def tagstart(name, attributes)
        if DIST_ARR.include?(name) || (DIST_CONFIG_ARR.include?(name) && @xmlpath.blank?)
          @distribution = { :cnames  => [], :logging => {}, :trusted_signers => {} }
        end
      end
      def tagend(name)
        case name
          when 'Marker'           then @result[:marker]                   = @text
          when 'NextMarker'       then @result[:next_marker]              = @text
          when 'MaxItems'         then @result[:max_items]                = @text.to_i
          when 'IsTruncated'      then @result[:is_truncated]             = @text == 'true' ? true : false
          when 'Origin'           then @distribution[:origin]             = @text
          when 'CallerReference'  then @distribution[:caller_reference]   = @text
          when 'CNAME'            then @distribution[:cnames]            << @text
          when 'Comment'          then @distribution[:comment]            = AcfInterface::unescape(@text)
          when 'Enabled'          then @distribution[:enabled]            = @text == 'true' ? true : false
          when 'Bucket'           then @distribution[:logging][:bucket]   = @text
          when 'Prefix'           then @distribution[:logging][:prefix]   = @text
          when 'OriginAccessIdentity'
                                  then @distribution[:origin_access_identity]               = @text
          when 'Self'             then @distribution[:trusted_signers][:self]               = @text
          when 'AwsAccountNumber' then @distribution[:trusted_signers][:aws_account_number] = @text
          when 'Id'               then @distribution[:aws_id]             = @text
          when 'Status'           then @distribution[:status]             = @text
          when 'LastModifiedTime' then @distribution[:last_modified_time] = Time.parse(@text)
          when 'DomainName'       then @distribution[:domain_name]        = @text
        end
        if DIST_ARR.include?(name) || (DIST_CONFIG_ARR.include?(name) && @xmlpath.blank?)
          @result[:distributions] << @distribution
        end
      end
    end
  end
end
