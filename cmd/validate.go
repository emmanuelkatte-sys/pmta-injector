package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"__MODULE_PLACEHOLDER__/config"
	"__MODULE_PLACEHOLDER__/email"

	"github.com/spf13/cobra"
)

var (
	sampleData string
)

// validateCmd 验证命令
var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "验证配置和模板",
	Long: `验证配置文件和邮件模板是否正确。

示例：
  # 验证模板
  pmta-injector validate --template template.html

  # 使用示例数据验证
  pmta-injector validate --template template.html \
    --sample-data '{"Email":"test@example.com","Name":"John"}'

  # 验证配置文件
  pmta-injector validate --config config.yaml`,
	RunE: runValidate,
}

func init() {
	validateCmd.Flags().StringVarP(&templateFile, "template", "t", "", "模板文件路径")
	validateCmd.Flags().StringVar(&sampleData, "sample-data", "", "示例数据（JSON格式）")
}

func runValidate(cmd *cobra.Command, args []string) error {
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("                    配置和模板验证")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	// 验证配置文件
	if cfgFile != "" {
		fmt.Printf("\n[配置文件验证]\n")
		fmt.Printf("  文件: %s\n", cfgFile)

		cfg, err := config.LoadFromFile(cfgFile)
		if err != nil {
			fmt.Printf("  状态: ❌ 失败\n")
			fmt.Printf("  错误: %v\n", err)
			return err
		}
		fmt.Printf("  状态: ✅ 通过\n")

		// 显示配置摘要
		fmt.Printf("\n  [配置摘要]\n")
		fmt.Printf("    发件人: %s <%s>\n", cfg.Sender.FromName, cfg.Sender.FromAddress)
		fmt.Printf("    虚拟MTA: %s\n", cfg.PMTA.VirtualMTA)
		fmt.Printf("    Pickup目录: %s\n", cfg.PMTA.PickupDir)
		fmt.Printf("    并发数: %d\n", cfg.Performance.Workers)
	}

	// 验证模板文件
	if templateFile != "" {
		fmt.Printf("\n[模板文件验证]\n")
		fmt.Printf("  文件: %s\n", templateFile)

		// 检查文件是否存在
		if _, err := os.Stat(templateFile); os.IsNotExist(err) {
			fmt.Printf("  状态: ❌ 文件不存在\n")
			return err
		}

		// 加载模板
		tmplEngine, err := email.NewTemplateEngine(templateFile)
		if err != nil {
			fmt.Printf("  状态: ❌ 模板解析失败\n")
			fmt.Printf("  错误: %v\n", err)
			return err
		}
		fmt.Printf("  状态: ✅ 模板解析成功\n")

		// 如果提供了示例数据，进行渲染测试
		if sampleData != "" {
			fmt.Printf("\n[模板渲染测试]\n")

			var data map[string]interface{}
			if err := json.Unmarshal([]byte(sampleData), &data); err != nil {
				fmt.Printf("  状态: ❌ 示例数据JSON解析失败\n")
				fmt.Printf("  错误: %v\n", err)
				return err
			}

			// 构建模板数据
			tmplData := email.NewTemplateData()
			for k, v := range data {
				switch k {
				case "Email", "email":
					tmplData.Email = fmt.Sprintf("%v", v)
				case "Name", "name":
					tmplData.Name = fmt.Sprintf("%v", v)
				case "FirstName", "firstName", "first_name":
					tmplData.FirstName = fmt.Sprintf("%v", v)
				case "LastName", "lastName", "last_name":
					tmplData.LastName = fmt.Sprintf("%v", v)
				default:
					tmplData.Data[k] = fmt.Sprintf("%v", v)
				}
			}

			// 渲染模板
			result, err := tmplEngine.Render(tmplData)
			if err != nil {
				fmt.Printf("  状态: ❌ 模板渲染失败\n")
				fmt.Printf("  错误: %v\n", err)
				return err
			}

			fmt.Printf("  状态: ✅ 模板渲染成功\n")
			fmt.Printf("  输出长度: %d 字节\n", len(result))

			// 显示渲染结果预览（前500字符）
			preview := result
			if len(preview) > 500 {
				preview = preview[:500] + "..."
			}
			fmt.Printf("\n[渲染结果预览]\n%s\n", preview)
		}
	}

	// 验证 Pickup 目录
	if cfgFile != "" {
		cfg, _ := config.LoadFromFile(cfgFile)
		fmt.Printf("\n[Pickup目录验证]\n")
		fmt.Printf("  路径: %s\n", cfg.PMTA.PickupDir)

		if info, err := os.Stat(cfg.PMTA.PickupDir); err != nil {
			fmt.Printf("  状态: ❌ 目录不存在或无法访问\n")
			fmt.Printf("  错误: %v\n", err)
		} else if !info.IsDir() {
			fmt.Printf("  状态: ❌ 路径不是目录\n")
		} else {
			// 检查写入权限
			testFile := cfg.PMTA.PickupDir + "/.write_test"
			if f, err := os.Create(testFile); err != nil {
				fmt.Printf("  状态: ⚠️ 目录存在但无写入权限\n")
				fmt.Printf("  错误: %v\n", err)
			} else {
				f.Close()
				os.Remove(testFile)
				fmt.Printf("  状态: ✅ 目录可写\n")
			}
		}
	}

	fmt.Println("\n═══════════════════════════════════════════════════════════════")
	fmt.Println("                      验证完成")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	return nil
}
