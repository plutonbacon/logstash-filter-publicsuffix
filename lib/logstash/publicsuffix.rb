# encoding: utf-8
require 'logstash/filters/base'
require 'logstash/namespace'
require "lru_redux"

# Parse domain names based on Mozilla's Public Suffix List.
class LogStash::Filters::PublicSuffix < LogStash::Filters::Base
  config_name "publicsuffix"

  # The field containing the domain name. If this field is an array only the
  # first value will ve used.
  config :source, :validate => :string, :required => true

  # The name of the field to assign domain suffix data into.
  #
  # If not specified domain suffix data will be stored in the root of the
  # event.
  config :target, :validate => :string

  # A string to prepend to all of the extracted keys
  config :prefix, :validate => :string, :default => ''

  public
  def register
    require 'public_suffix'
  end # def register

  public
  def filter(event)
    return unless filter?(event)

    domain = event[@source]
    domain = domain.first if domain.is_a? Array

    begin
      suffixes = parse_domain(domain)
    rescue StandardError => e
      @logger.error("Unknown error while parsing domain", :exception => e, :field => @source, :event => event)
      return
    end

    return unless suffixes

    target = @target.nil? ? event : (event[@target] ||= {})
    write_to_target(target, suffixes)

    filter_matched(event)
  end # def filter

  def parse_domain(domain)
    return unless domain

    suffixes = PublicSuffix.parse(domain)
  end # def parse_domain

  def write_to_target(target, suffixes)
    target[@prefix + "tld"] = suffixes.tld.force_encoding(Encoding::UTF_8) if suffixes.tld
    target[@prefix + "sld"] = suffixes.sld.force_encoding(Encoding::UTF_8) if suffixes.sld
    target[@prefix + "trd"] = suffixes.trd.force_encoding(Encoding::UTF_8) if suffixes.trd
  end # def write_to_target

end # class LogStash::Filters::PublicSuffix
