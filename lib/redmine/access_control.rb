# Redmine - project management software
# Copyright (C) 2006-2017  Jean-Philippe Lang
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

module Redmine
  module AccessControl

    class << self
      def map
        mapper = Mapper.new
        yield mapper
        @permissions ||= []
        @permissions += mapper.mapped_permissions
      end

      def permissions
        @permissions
      end

      # Returns the permission of given name or nil if it wasn't found
      # Argument should be a symbol
      def permission(name)
        permissions.detect {|p| p.name == name}
      end

      # Returns the actions that are allowed by the permission of given name
      def allowed_actions(permission_name)
        perm = permission(permission_name)
        perm ? perm.actions : []
      end

      def public_permissions
        @public_permissions ||= @permissions.select {|p| p.public?}
      end

      def members_only_permissions
        @members_only_permissions ||= @permissions.select {|p| p.require_member?}
      end

      def loggedin_only_permissions
        @loggedin_only_permissions ||= @permissions.select {|p| p.require_loggedin?}
      end

      def read_action?(action)
        if action.is_a?(Symbol)
          perm = permission(action)
          !perm.nil? && perm.read?
        elsif action.is_a?(Hash)
          s = "#{action[:controller]}/#{action[:action]}"
          permissions.detect {|p| p.actions.include?(s) && p.read?}.present?
        else
          raise ArgumentError.new("Symbol or a Hash expected, #{action.class.name} given: #{action}")
        end
      end

      def available_project_modules
        @available_project_modules ||= @permissions.collect(&:project_module).uniq.compact
      end

      def modules_permissions(modules)
        @permissions.select {|p| p.project_module.nil? || modules.include?(p.project_module.to_s)}
      end
    end

    class Mapper
      def initialize
        @project_module = nil
      end
      # 构建一个允许访问路径
      # name symbal 指定访问路径的名称
      # hash
      # 如：{:timelog => [:index, :report, :show]}
      # 它定义一个允许访问的controller和其action
      # options 定义其访问的属性 
      def permission(name, hash, options={})
        @permissions ||= []
        options.merge!(:project_module => @project_module)
        @permissions << Permission.new(name, hash, options)
      end

      # 给指定的模块设置一些访问权限
      # map.project_module :news do |map|
      #   map.permission :view_news, {:news => [:index, :show]}, :read => true
      # end
      def project_module(name, options={})
        @project_module = name
        yield self # self等于Mapper实例
        @project_module = nil
      end

      # 返回映射后的权限
      def mapped_permissions
        @permissions
      end
    end

    class Permission
      attr_reader :name, :actions, :project_module

      # name Symbal 权限名称
      # hash {:news => [:index, :show]} 一个hash代表controller和指定的action
      # options 访问权限参数
      # { :public => true/false, :require => :member/:loggedin, :read => true/false }
      def initialize(name, hash, options)
        @name = name
        @actions = []
        @public = options[:public] || false
        @require = options[:require]
        @read = options[:read] || false
        @project_module = options[:project_module]
        # 收集权限列表到 @actions 中
        # hash => {:timelog => [:new, :create]} to
        # [ 'timelog/new', ''timelog/create ]
        hash.each do |controller, actions|
          if actions.is_a? Array
            @actions << actions.collect {|action| "#{controller}/#{action}"}
          else
            @actions << "#{controller}/#{actions}"
          end
        end
        @actions.flatten!
      end

      def public?
        @public
      end

      def require_member?
        @require && @require == :member
      end

      def require_loggedin?
        @require && (@require == :member || @require == :loggedin)
      end

      def read?
        @read
      end
    end
  end
end
